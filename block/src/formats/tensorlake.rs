// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Tensorlake rootfs overlay disk image.
//!
//! This backend embeds Tensorlake's rootfs overlay model directly behind
//! virtio-blk. The VMM opens a small JSON spec that points at a base rootfs,
//! committed native-overlay layers, and a writable live overlay. Reads are
//! resolved through the overlay stack and writes are captured in the live
//! overlay, so the dataplane does not need to run a separate block server.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use crate::async_io::{
    AsyncIo, AsyncIoCompletion, AsyncIoError, AsyncIoOperation, BorrowedDiskFd, DiskFileError,
};
use crate::error::{BlockError, BlockErrorKind, BlockResult};
use crate::sparse::punch_hole;
use crate::{DiskTopology, SECTOR_SIZE, disk_file};

const SPEC_VERSION: u32 = 1;
const DEFAULT_BLOCK_SIZE: u64 = 4096;

/// Disk wrapper for a Tensorlake rootfs overlay spec.
#[derive(Debug)]
pub struct TensorlakeRootfsDisk {
    state: Arc<TensorlakeRootfsState>,
    lock_file: File,
}

#[derive(Debug)]
struct TensorlakeRootfsState {
    logical_size: u64,
    block_size: u64,
    base_path: PathBuf,
    live_path: PathBuf,
    live_index_path: Option<PathBuf>,
    base: File,
    layers_oldest_to_newest: Vec<CommittedLayer>,
    live: Mutex<LiveOverlay>,
    readonly: bool,
}

#[derive(Debug)]
struct CommittedLayer {
    path: PathBuf,
    file: File,
    dirty_runs: Vec<BlockRun>,
    zero_runs: Vec<BlockRun>,
}

#[derive(Debug)]
struct LiveOverlay {
    file: File,
    dirty_blocks: BTreeSet<u64>,
    zero_blocks: BTreeSet<u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct TensorlakeRootfsSpec {
    version: u32,
    logical_size: u64,
    #[serde(default = "default_block_size")]
    block_size: u64,
    base_path: PathBuf,
    live_overlay_path: PathBuf,
    #[serde(default)]
    live_index_path: Option<PathBuf>,
    #[serde(default)]
    layers: Vec<TensorlakeLayerSpec>,
}

#[derive(Clone, Debug, Deserialize)]
struct TensorlakeLayerSpec {
    path: PathBuf,
    #[serde(default)]
    dirty_runs: Vec<BlockRun>,
    #[serde(default)]
    zero_runs: Vec<BlockRun>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BlockRun {
    start_block: u64,
    block_count: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct LiveOverlayIndex {
    version: u32,
    #[serde(default)]
    dirty_runs: Vec<BlockRun>,
    #[serde(default)]
    zero_runs: Vec<BlockRun>,
}

impl TensorlakeRootfsDisk {
    /// Opens a Tensorlake rootfs overlay spec from `spec_path`.
    pub fn open(spec_path: &Path, readonly: bool) -> BlockResult<Self> {
        let spec_file = open_readonly(spec_path)?;
        let spec: TensorlakeRootfsSpec = serde_json::from_reader(&spec_file)
            .map_err(|e| BlockError::new(BlockErrorKind::InvalidFormat, e).with_path(spec_path))?;
        validate_spec(&spec, spec_path)?;

        let base_path = resolve_spec_path(spec_path, &spec.base_path);
        let live_path = resolve_spec_path(spec_path, &spec.live_overlay_path);
        let live_index_path = spec
            .live_index_path
            .as_deref()
            .map(|path| resolve_spec_path(spec_path, path));
        if !readonly && live_index_path.is_none() {
            return Err(invalid_spec(
                spec_path,
                "live_index_path is required for writable Tensorlake rootfs disks",
            ));
        }
        let base = open_readonly(&base_path)?;
        validate_file_covers(&base, spec.logical_size, &base_path)?;

        let mut layers_oldest_to_newest = Vec::with_capacity(spec.layers.len());
        for layer in &spec.layers {
            layers_oldest_to_newest.push(open_committed_layer(spec_path, layer, spec.block_size)?);
        }

        let live_file = open_live_overlay(&live_path, spec.logical_size, readonly)?;
        let lock_file = live_file
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        let live = load_live_overlay(
            live_file,
            live_index_path.as_deref(),
            spec.block_size,
            spec.logical_size,
        )?;

        Ok(Self {
            state: Arc::new(TensorlakeRootfsState {
                logical_size: spec.logical_size,
                block_size: spec.block_size,
                base_path,
                live_path,
                live_index_path,
                base,
                layers_oldest_to_newest,
                live: Mutex::new(live),
                readonly,
            }),
            lock_file,
        })
    }
}

fn default_block_size() -> u64 {
    DEFAULT_BLOCK_SIZE
}

fn open_readonly(path: &Path) -> BlockResult<File> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_path(path))
}

fn open_live_overlay(path: &Path, logical_size: u64, readonly: bool) -> BlockResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(!readonly);
    if !readonly {
        options.create(true);
    }

    let file = options
        .open(path)
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_path(path))?;
    if !readonly {
        file.set_len(logical_size)
            .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_path(path))?;
    }
    validate_file_covers(&file, logical_size, path)?;
    Ok(file)
}

fn load_live_overlay(
    file: File,
    index_path: Option<&Path>,
    block_size: u64,
    logical_size: u64,
) -> BlockResult<LiveOverlay> {
    let Some(index_path) = index_path else {
        return Ok(LiveOverlay {
            file,
            dirty_blocks: BTreeSet::new(),
            zero_blocks: BTreeSet::new(),
        });
    };
    if !index_path.exists() {
        return Ok(LiveOverlay {
            file,
            dirty_blocks: BTreeSet::new(),
            zero_blocks: BTreeSet::new(),
        });
    }

    let index_file = open_readonly(index_path)?;
    let index: LiveOverlayIndex = serde_json::from_reader(index_file)
        .map_err(|e| BlockError::new(BlockErrorKind::InvalidFormat, e).with_path(index_path))?;
    if index.version != SPEC_VERSION {
        return Err(invalid_spec(
            index_path,
            format!(
                "unsupported Tensorlake live overlay index version {}, expected {}",
                index.version, SPEC_VERSION
            ),
        ));
    }

    let max_blocks = logical_size.div_ceil(block_size);
    let mut dirty_blocks = BTreeSet::new();
    let mut zero_blocks = BTreeSet::new();
    for run in &index.dirty_runs {
        add_run_blocks(&mut dirty_blocks, *run, block_size, max_blocks, index_path)?;
    }
    for run in &index.zero_runs {
        add_run_blocks(&mut zero_blocks, *run, block_size, max_blocks, index_path)?;
    }
    if let Some(block) = dirty_blocks.intersection(&zero_blocks).next() {
        return Err(invalid_spec(
            index_path,
            format!("live overlay block {block} is both dirty and zero"),
        ));
    }

    Ok(LiveOverlay {
        file,
        dirty_blocks,
        zero_blocks,
    })
}

fn add_run_blocks(
    blocks: &mut BTreeSet<u64>,
    run: BlockRun,
    block_size: u64,
    max_blocks: u64,
    path: &Path,
) -> BlockResult<()> {
    validate_run(run, block_size, path)?;
    let end = run.end_block_exclusive()?;
    if end > max_blocks {
        return Err(invalid_spec(
            path,
            format!("block run ends at block {end}, beyond max block {max_blocks}"),
        ));
    }
    for block in run.start_block..end {
        blocks.insert(block);
    }
    Ok(())
}

fn open_committed_layer(
    spec_path: &Path,
    spec: &TensorlakeLayerSpec,
    block_size: u64,
) -> BlockResult<CommittedLayer> {
    let path = resolve_spec_path(spec_path, &spec.path);
    let file = open_readonly(&path)?;
    for run in spec.dirty_runs.iter().chain(&spec.zero_runs) {
        validate_run(*run, block_size, &path)?;
    }
    for run in &spec.dirty_runs {
        validate_file_covers(&file, run.end_byte_offset(block_size)?, &path)?;
    }

    Ok(CommittedLayer {
        path,
        file,
        dirty_runs: spec.dirty_runs.clone(),
        zero_runs: spec.zero_runs.clone(),
    })
}

fn resolve_spec_path(spec_path: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        spec_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn validate_spec(spec: &TensorlakeRootfsSpec, spec_path: &Path) -> BlockResult<()> {
    if spec.version != SPEC_VERSION {
        return Err(invalid_spec(
            spec_path,
            format!(
                "unsupported Tensorlake rootfs spec version {}, expected {}",
                spec.version, SPEC_VERSION
            ),
        ));
    }
    if spec.logical_size == 0 {
        return Err(invalid_spec(
            spec_path,
            "logical_size must be greater than zero",
        ));
    }
    if spec.block_size == 0 || !spec.block_size.is_multiple_of(SECTOR_SIZE) {
        return Err(invalid_spec(
            spec_path,
            format!(
                "block_size must be a non-zero multiple of {SECTOR_SIZE}, got {}",
                spec.block_size
            ),
        ));
    }
    Ok(())
}

fn validate_run(run: BlockRun, block_size: u64, path: &Path) -> BlockResult<()> {
    if run.block_count == 0 {
        return Err(invalid_spec(path, "block run block_count must be non-zero"));
    }
    let _ = run.end_byte_offset(block_size)?;
    Ok(())
}

fn validate_file_covers(file: &File, required_len: u64, path: &Path) -> BlockResult<()> {
    let len = file
        .metadata()
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_path(path))?
        .len();
    if len < required_len {
        return Err(invalid_spec(
            path,
            format!("file length {len} is smaller than required length {required_len}"),
        ));
    }
    Ok(())
}

fn invalid_spec(path: &Path, message: impl Into<String>) -> BlockError {
    BlockError::new(
        BlockErrorKind::InvalidFormat,
        io::Error::new(ErrorKind::InvalidData, message.into()),
    )
    .with_path(path)
}

impl BlockRun {
    fn end_block_exclusive(self) -> BlockResult<u64> {
        self.start_block
            .checked_add(self.block_count)
            .ok_or_else(|| BlockError::from_kind(BlockErrorKind::Overflow))
    }

    fn contains_block(self, block: u64) -> bool {
        block >= self.start_block
            && self
                .end_block_exclusive()
                .is_ok_and(|end_block| block < end_block)
    }

    fn end_byte_offset(self, block_size: u64) -> BlockResult<u64> {
        self.end_block_exclusive()?
            .checked_mul(block_size)
            .ok_or_else(|| BlockError::from_kind(BlockErrorKind::Overflow))
    }
}

impl TensorlakeRootfsState {
    fn ensure_range_in_bounds(&self, offset: u64, len: usize) -> io::Result<()> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "I/O range overflows u64"))?;
        if end > self.logical_size {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "I/O range [{offset}, {end}) exceeds logical size {}",
                    self.logical_size
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn read_at(&self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        self.ensure_range_in_bounds(offset, data.len())?;
        let mut done = 0;
        while done < data.len() {
            let absolute_offset = offset + done as u64;
            let segment_len = self.segment_len(absolute_offset, data.len() - done);
            self.read_segment(absolute_offset, &mut data[done..done + segment_len], true)?;
            done += segment_len;
        }
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.readonly {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "Tensorlake rootfs disk is readonly",
            ));
        }
        self.ensure_range_in_bounds(offset, data.len())?;
        let mut done = 0;
        while done < data.len() {
            let absolute_offset = offset + done as u64;
            let segment_len = self.segment_len(absolute_offset, data.len() - done);
            self.write_segment(absolute_offset, &data[done..done + segment_len])?;
            done += segment_len;
        }
        Ok(())
    }

    fn zero_at(&self, offset: u64, len: u64) -> io::Result<()> {
        if self.readonly {
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "Tensorlake rootfs disk is readonly",
            ));
        }
        self.ensure_range_in_bounds(offset, len as usize)?;
        let mut done = 0;
        while done < len {
            let absolute_offset = offset + done;
            let segment_len = self.segment_len(absolute_offset, (len - done) as usize) as u64;
            self.zero_segment(absolute_offset, segment_len as usize)?;
            done += segment_len;
        }
        Ok(())
    }

    fn sync_live(&self) -> io::Result<()> {
        let live = self
            .live
            .lock()
            .map_err(|_| io::Error::other("Tensorlake live overlay lock poisoned"))?;
        live.file.sync_data()?;
        if let Some(index_path) = &self.live_index_path {
            persist_live_index(index_path, &live)?;
        }
        Ok(())
    }

    fn segment_len(&self, absolute_offset: u64, remaining: usize) -> usize {
        let block_offset = absolute_offset % self.block_size;
        let block_remaining = self.block_size - block_offset;
        let disk_remaining = self.logical_size - absolute_offset;
        remaining.min(block_remaining.min(disk_remaining) as usize)
    }

    fn read_segment(
        &self,
        absolute_offset: u64,
        data: &mut [u8],
        include_live: bool,
    ) -> io::Result<()> {
        let block = absolute_offset / self.block_size;
        if include_live {
            let live = self
                .live
                .lock()
                .map_err(|_| io::Error::other("Tensorlake live overlay lock poisoned"))?;
            if live.zero_blocks.contains(&block) {
                data.fill(0);
                return Ok(());
            }
            if live.dirty_blocks.contains(&block) {
                return live.file.read_exact_at(data, absolute_offset);
            }
        }

        self.read_committed_segment(block, absolute_offset, data)
    }

    fn read_committed_segment(
        &self,
        block: u64,
        absolute_offset: u64,
        data: &mut [u8],
    ) -> io::Result<()> {
        for layer in self.layers_oldest_to_newest.iter().rev() {
            if layer.has_zero_block(block) {
                data.fill(0);
                return Ok(());
            }
            if layer.has_dirty_block(block) {
                return layer.file.read_exact_at(data, absolute_offset);
            }
        }
        self.base.read_exact_at(data, absolute_offset)
    }

    fn write_segment(&self, absolute_offset: u64, data: &[u8]) -> io::Result<()> {
        let block = absolute_offset / self.block_size;
        let valid_block_len = self.valid_block_len(block);
        let block_start = block * self.block_size;
        let covers_entire_block =
            absolute_offset == block_start && data.len() as u64 == valid_block_len;
        let mut live = self
            .live
            .lock()
            .map_err(|_| io::Error::other("Tensorlake live overlay lock poisoned"))?;

        if !covers_entire_block
            && !live.dirty_blocks.contains(&block)
            && !live.zero_blocks.contains(&block)
        {
            self.seed_live_block(&mut live, block, valid_block_len)?;
        }
        if live.zero_blocks.remove(&block) {
            self.seed_zero_block(&mut live, block, valid_block_len)?;
        }
        live.dirty_blocks.insert(block);
        live.file.write_all_at(data, absolute_offset)
    }

    fn zero_segment(&self, absolute_offset: u64, len: usize) -> io::Result<()> {
        let block = absolute_offset / self.block_size;
        let valid_block_len = self.valid_block_len(block);
        let block_start = block * self.block_size;
        let covers_entire_block = absolute_offset == block_start && len as u64 == valid_block_len;
        let mut live = self
            .live
            .lock()
            .map_err(|_| io::Error::other("Tensorlake live overlay lock poisoned"))?;

        if covers_entire_block {
            live.dirty_blocks.remove(&block);
            live.zero_blocks.insert(block);
            reclaim_live_block(&live.file, block_start, valid_block_len);
            Ok(())
        } else {
            if !live.dirty_blocks.contains(&block) {
                if live.zero_blocks.remove(&block) {
                    self.seed_zero_block(&mut live, block, valid_block_len)?;
                } else {
                    self.seed_live_block(&mut live, block, valid_block_len)?;
                }
            }
            live.dirty_blocks.insert(block);
            let zeroes = vec![0; len];
            live.file.write_all_at(&zeroes, absolute_offset)
        }
    }

    fn seed_live_block(
        &self,
        live: &mut LiveOverlay,
        block: u64,
        valid_block_len: u64,
    ) -> io::Result<()> {
        let block_start = block * self.block_size;
        let mut block_data = vec![0; valid_block_len as usize];
        self.read_committed_segment(block, block_start, &mut block_data)?;
        live.file.write_all_at(&block_data, block_start)
    }

    fn seed_zero_block(
        &self,
        live: &mut LiveOverlay,
        block: u64,
        valid_block_len: u64,
    ) -> io::Result<()> {
        let block_start = block * self.block_size;
        let block_data = vec![0; valid_block_len as usize];
        live.file.write_all_at(&block_data, block_start)
    }

    fn valid_block_len(&self, block: u64) -> u64 {
        let block_start = block * self.block_size;
        self.block_size.min(self.logical_size - block_start)
    }
}

fn reclaim_live_block(file: &File, offset: u64, len: u64) {
    let _ = punch_hole(file.as_raw_fd(), false, offset, len);
}

fn persist_live_index(path: &Path, live: &LiveOverlay) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
    }
    let index = LiveOverlayIndex {
        version: SPEC_VERSION,
        dirty_runs: runs_from_blocks(&live.dirty_blocks),
        zero_runs: runs_from_blocks(&live.zero_blocks),
    };
    let bytes = serde_json::to_vec_pretty(&index).map_err(io::Error::other)?;
    let temp_path = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("live-index.json"),
        uuid::Uuid::new_v4()
    ));
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    temp_file.write_all(&bytes)?;
    temp_file.sync_all()?;
    drop(temp_file);

    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }

    if let Some(parent) = parent {
        sync_directory(parent)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)?
        .sync_all()
}

fn runs_from_blocks(blocks: &BTreeSet<u64>) -> Vec<BlockRun> {
    let mut runs = Vec::new();
    let mut current_start = None;
    let mut previous = None;
    for block in blocks {
        match (current_start, previous) {
            (Some(start), Some(prev)) if *block == prev + 1 => {
                previous = Some(*block);
                current_start = Some(start);
            }
            (Some(start), Some(prev)) => {
                runs.push(BlockRun {
                    start_block: start,
                    block_count: prev - start + 1,
                });
                current_start = Some(*block);
                previous = Some(*block);
            }
            _ => {
                current_start = Some(*block);
                previous = Some(*block);
            }
        }
    }
    if let (Some(start), Some(prev)) = (current_start, previous) {
        runs.push(BlockRun {
            start_block: start,
            block_count: prev - start + 1,
        });
    }
    runs
}

impl CommittedLayer {
    fn has_dirty_block(&self, block: u64) -> bool {
        self.dirty_runs.iter().any(|run| run.contains_block(block))
    }

    fn has_zero_block(&self, block: u64) -> bool {
        self.zero_runs.iter().any(|run| run.contains_block(block))
    }
}

impl disk_file::DiskSize for TensorlakeRootfsDisk {
    fn logical_size(&self) -> BlockResult<u64> {
        Ok(self.state.logical_size)
    }
}

impl disk_file::PhysicalSize for TensorlakeRootfsDisk {
    fn physical_size(&self) -> BlockResult<u64> {
        let mut size = allocated_size(&self.state.base_path)?;
        size = size.saturating_add(allocated_size(&self.state.live_path)?);
        for layer in &self.state.layers_oldest_to_newest {
            size = size.saturating_add(allocated_size(&layer.path)?);
        }
        Ok(size)
    }
}

fn allocated_size(path: &Path) -> BlockResult<u64> {
    path.metadata()
        .map(|metadata| metadata.st_blocks().saturating_mul(512))
        .map_err(|e| BlockError::new(BlockErrorKind::Io, e).with_path(path))
}

impl disk_file::DiskFd for TensorlakeRootfsDisk {
    fn fd(&self) -> BorrowedDiskFd<'_> {
        BorrowedDiskFd::new(self.lock_file.as_raw_fd())
    }
}

impl disk_file::Geometry for TensorlakeRootfsDisk {
    fn topology(&self) -> DiskTopology {
        DiskTopology {
            logical_block_size: SECTOR_SIZE,
            physical_block_size: self.state.block_size,
            minimum_io_size: SECTOR_SIZE,
            optimal_io_size: self.state.block_size,
        }
    }
}

impl disk_file::SparseCapable for TensorlakeRootfsDisk {
    fn supports_sparse_operations(&self) -> bool {
        !self.state.readonly
    }

    fn supports_zero_flag(&self) -> bool {
        !self.state.readonly
    }
}

impl disk_file::Resizable for TensorlakeRootfsDisk {
    fn resize(&mut self, size: u64) -> BlockResult<()> {
        if size == self.state.logical_size {
            Ok(())
        } else {
            Err(BlockError::new(
                BlockErrorKind::UnsupportedFeature,
                io::Error::other("Tensorlake rootfs disk resize is not supported"),
            ))
        }
    }
}

impl disk_file::DiskFile for TensorlakeRootfsDisk {}

impl disk_file::AsyncDiskFile for TensorlakeRootfsDisk {
    fn try_clone(&self) -> BlockResult<Box<dyn disk_file::AsyncDiskFile>> {
        let lock_file = self
            .lock_file
            .try_clone()
            .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::Clone(e)))?;
        Ok(Box::new(Self {
            state: Arc::clone(&self.state),
            lock_file,
        }))
    }

    fn create_async_io(&self, _ring_depth: u32) -> BlockResult<Box<dyn AsyncIo>> {
        Ok(Box::new(TensorlakeRootfsSyncIo {
            state: Arc::clone(&self.state),
            eventfd: EventFd::new(libc::EFD_NONBLOCK)
                .map_err(|e| BlockError::new(BlockErrorKind::Io, DiskFileError::NewAsyncIo(e)))?,
            completion_list: VecDeque::new(),
        }))
    }
}

struct TensorlakeRootfsSyncIo {
    state: Arc<TensorlakeRootfsState>,
    eventfd: EventFd,
    completion_list: VecDeque<AsyncIoCompletion>,
}

impl TensorlakeRootfsSyncIo {
    fn complete(&mut self, op: AsyncIoOperation, result: i32) {
        self.completion_list
            .push_back(AsyncIoCompletion::from_operation(op, result));
        self.eventfd.write(1).unwrap();
    }

    fn submit_read(&mut self, mut op: AsyncIoOperation) -> io::Result<i32> {
        let mut buffer = vec![0; op.total_len()];
        self.state.read_at(op.offset() as u64, &mut buffer)?;
        op.write_bytes_at(0, &buffer)?;
        let result = buffer.len() as i32;
        self.complete(op, result);
        Ok(result)
    }

    fn submit_write(&mut self, op: AsyncIoOperation) -> io::Result<i32> {
        let mut buffer = vec![0; op.total_len()];
        op.read_bytes_at(0, &mut buffer)?;
        self.state.write_at(op.offset() as u64, &buffer)?;
        let result = buffer.len() as i32;
        self.complete(op, result);
        Ok(result)
    }
}

impl AsyncIo for TensorlakeRootfsSyncIo {
    fn notifier(&self) -> &EventFd {
        &self.eventfd
    }

    fn alignment(&self) -> u64 {
        SECTOR_SIZE
    }

    fn submit_data_operation(
        &mut self,
        op: AsyncIoOperation,
    ) -> crate::async_io::AsyncIoResult<()> {
        if op.offset() < 0 {
            let error = io::Error::new(ErrorKind::InvalidInput, "negative disk offset");
            return Err(if op.is_read() {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            });
        }

        let is_read = op.is_read();
        let result = if is_read {
            self.submit_read(op).map(|_| ())
        } else {
            self.submit_write(op).map(|_| ())
        };
        result.map_err(|error| {
            if is_read {
                AsyncIoError::ReadVectored(error)
            } else {
                AsyncIoError::WriteVectored(error)
            }
        })
    }

    fn fsync(&mut self, user_data: Option<u64>) -> crate::async_io::AsyncIoResult<()> {
        self.state.sync_live().map_err(AsyncIoError::Fsync)?;
        if let Some(user_data) = user_data {
            self.completion_list
                .push_back(AsyncIoCompletion::new(user_data, 0, None));
            self.eventfd.write(1).unwrap();
        }
        Ok(())
    }

    fn next_completed_request(&mut self) -> Option<AsyncIoCompletion> {
        self.completion_list.pop_front()
    }

    fn punch_hole(
        &mut self,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> crate::async_io::AsyncIoResult<()> {
        self.state
            .zero_at(offset, length)
            .map_err(AsyncIoError::PunchHole)?;
        self.completion_list
            .push_back(AsyncIoCompletion::new(user_data, 0, None));
        self.eventfd.write(1).unwrap();
        Ok(())
    }

    fn write_zeroes(
        &mut self,
        offset: u64,
        length: u64,
        user_data: u64,
    ) -> crate::async_io::AsyncIoResult<()> {
        self.state
            .zero_at(offset, length)
            .map_err(AsyncIoError::WriteZeroes)?;
        self.completion_list
            .push_back(AsyncIoCompletion::new(user_data, 0, None));
        self.eventfd.write(1).unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use std::io::Write;

    use serde_json::json;
    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::async_io::{AsyncIo, OwnedIoBuffer};
    use crate::disk_file::{AsyncDiskFile, DiskSize, PhysicalSize};

    const TEST_BLOCK_SIZE: usize = SECTOR_SIZE as usize;
    const TEST_LOGICAL_SIZE: u64 = (TEST_BLOCK_SIZE * 4) as u64;

    fn write_file(path: &Path, data: &[u8]) {
        let mut file = File::create(path).unwrap();
        file.write_all(data).unwrap();
        file.sync_all().unwrap();
    }

    fn write_sparse_file(path: &Path, size: u64, writes: &[(u64, &[u8])]) {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.set_len(size).unwrap();
        for (offset, data) in writes {
            file.write_all_at(data, *offset).unwrap();
        }
        file.sync_all().unwrap();
    }

    fn make_spec(dir: &Path) -> PathBuf {
        let spec_path = dir.join("tensorlake-rootfs.json");
        let spec = json!({
            "version": 1,
            "logical_size": TEST_LOGICAL_SIZE,
            "block_size": TEST_BLOCK_SIZE,
            "base_path": "base.img",
            "live_overlay_path": "live.img",
            "live_index_path": "live.index.json",
            "layers": [
                {
                    "path": "layer0.img",
                    "dirty_runs": [{"start_block": 1, "block_count": 1}],
                    "zero_runs": [{"start_block": 2, "block_count": 1}]
                }
            ]
        });
        write_file(&spec_path, spec.to_string().as_bytes());
        spec_path
    }

    fn make_disk() -> (TempDir, TensorlakeRootfsDisk) {
        let dir = TempDir::new_with_prefix("/tmp/ch-tensorlake").unwrap();
        let base_path = dir.as_path().join("base.img");
        let layer_path = dir.as_path().join("layer0.img");
        let mut base = Vec::with_capacity(TEST_LOGICAL_SIZE as usize);
        base.extend(vec![b'a'; TEST_BLOCK_SIZE]);
        base.extend(vec![b'b'; TEST_BLOCK_SIZE]);
        base.extend(vec![b'c'; TEST_BLOCK_SIZE]);
        base.extend(vec![b'd'; TEST_BLOCK_SIZE]);
        write_file(&base_path, &base);
        let layer_block = vec![b'E'; TEST_BLOCK_SIZE];
        write_sparse_file(
            &layer_path,
            TEST_LOGICAL_SIZE,
            &[(TEST_BLOCK_SIZE as u64, &layer_block)],
        );
        let spec_path = make_spec(dir.as_path());
        let disk = TensorlakeRootfsDisk::open(&spec_path, false).unwrap();
        (dir, disk)
    }

    fn read_vec(io: &mut dyn AsyncIo, offset: u64, len: usize) -> Vec<u8> {
        let buffer = OwnedIoBuffer::new(len, SECTOR_SIZE as usize).unwrap();
        io.read_to_vec(offset as libc::off_t, buffer, 7).unwrap();
        let completion = io.next_completed_request().unwrap();
        assert_eq!(completion.user_data, 7);
        assert_eq!(completion.result, len as i32);
        completion.buffer.unwrap().as_slice().to_vec()
    }

    fn write_vec(io: &mut dyn AsyncIo, offset: u64, data: &[u8]) {
        let mut buffer = OwnedIoBuffer::new(data.len(), SECTOR_SIZE as usize).unwrap();
        buffer.as_mut_slice().copy_from_slice(data);
        io.write_from_vec(offset as libc::off_t, buffer, 8).unwrap();
        let completion = io.next_completed_request().unwrap();
        assert_eq!(completion.user_data, 8);
        assert_eq!(completion.result, data.len() as i32);
    }

    #[test]
    fn reads_base_dirty_and_zero_layers() {
        let (_dir, disk) = make_disk();
        let mut io = disk.create_async_io(128).unwrap();

        assert_eq!(disk.logical_size().unwrap(), TEST_LOGICAL_SIZE);
        assert_eq!(read_vec(io.as_mut(), 0, 4), b"aaaa");
        assert_eq!(read_vec(io.as_mut(), TEST_BLOCK_SIZE as u64, 4), b"EEEE");
        assert_eq!(
            read_vec(io.as_mut(), (TEST_BLOCK_SIZE * 2) as u64, 4),
            b"\0\0\0\0"
        );
        assert_eq!(
            read_vec(io.as_mut(), (TEST_BLOCK_SIZE * 3) as u64, 4),
            b"dddd"
        );
    }

    #[test]
    fn partial_write_seeds_from_committed_layers() {
        let (_dir, disk) = make_disk();
        let mut io = disk.create_async_io(128).unwrap();

        write_vec(io.as_mut(), TEST_BLOCK_SIZE as u64 + 2, b"xy");

        assert_eq!(read_vec(io.as_mut(), TEST_BLOCK_SIZE as u64, 4), b"EExy");
        assert_eq!(
            read_vec(io.as_mut(), (TEST_BLOCK_SIZE * 2) as u64, 4),
            b"\0\0\0\0"
        );
    }

    #[test]
    fn zeroes_override_lower_layers_without_allocating_dirty_data() {
        let (_dir, disk) = make_disk();
        let mut io = disk.create_async_io(128).unwrap();

        io.write_zeroes(TEST_BLOCK_SIZE as u64, TEST_BLOCK_SIZE as u64, 9)
            .unwrap();
        let completion = io.next_completed_request().unwrap();
        assert_eq!(completion.user_data, 9);
        assert_eq!(completion.result, 0);

        assert_eq!(
            read_vec(io.as_mut(), TEST_BLOCK_SIZE as u64, 4),
            b"\0\0\0\0"
        );
        assert_eq!(
            read_vec(io.as_mut(), (TEST_BLOCK_SIZE * 3) as u64, 4),
            b"dddd"
        );
    }

    #[test]
    fn cloned_handles_share_live_overlay_state() {
        let (_dir, disk) = make_disk();
        let mut writer = disk.create_async_io(128).unwrap();
        let cloned = disk.try_clone().unwrap();
        let mut reader = cloned.create_async_io(128).unwrap();

        write_vec(writer.as_mut(), (TEST_BLOCK_SIZE * 3) as u64, b"zzzz");

        assert_eq!(
            read_vec(reader.as_mut(), (TEST_BLOCK_SIZE * 3) as u64, 4),
            b"zzzz"
        );
    }

    #[test]
    fn reports_allocated_size_across_all_files() {
        let (_dir, disk) = make_disk();

        assert!(disk.physical_size().unwrap() > 0);
    }

    #[test]
    fn fsync_persists_live_overlay_index_for_reopen() {
        let (dir, disk) = make_disk();
        let mut io = disk.create_async_io(128).unwrap();

        write_vec(io.as_mut(), TEST_BLOCK_SIZE as u64 + 2, b"xy");
        io.write_zeroes((TEST_BLOCK_SIZE * 2) as u64, TEST_BLOCK_SIZE as u64, 9)
            .unwrap();
        let _ = io.next_completed_request().unwrap();
        io.fsync(Some(10)).unwrap();
        let completion = io.next_completed_request().unwrap();
        assert_eq!(completion.user_data, 10);

        let spec_path = dir.as_path().join("tensorlake-rootfs.json");
        let reopened = TensorlakeRootfsDisk::open(&spec_path, false).unwrap();
        let mut reopened_io = reopened.create_async_io(128).unwrap();
        assert_eq!(
            read_vec(reopened_io.as_mut(), TEST_BLOCK_SIZE as u64, 4),
            b"EExy"
        );
        assert_eq!(
            read_vec(reopened_io.as_mut(), (TEST_BLOCK_SIZE * 2) as u64, 4),
            b"\0\0\0\0"
        );
    }

    #[test]
    fn writable_disk_requires_live_index_path() {
        let dir = TempDir::new_with_prefix("/tmp/ch-tensorlake").unwrap();
        let base_path = dir.as_path().join("base.img");
        write_file(&base_path, &vec![b'a'; TEST_LOGICAL_SIZE as usize]);
        let spec_path = dir.as_path().join("tensorlake-rootfs.json");
        let spec = json!({
            "version": 1,
            "logical_size": TEST_LOGICAL_SIZE,
            "block_size": TEST_BLOCK_SIZE,
            "base_path": "base.img",
            "live_overlay_path": "live.img",
            "layers": []
        });
        write_file(&spec_path, spec.to_string().as_bytes());

        let error = TensorlakeRootfsDisk::open(&spec_path, false).unwrap_err();
        assert!(format!("{error:?}").contains("live_index_path is required"));
    }
}
