use std::{
    error::Error,
    ops::{Div, Rem},
};

use crate::stream::{LengthType, OffsetType, Stream};

trait MultipleBlockReaderWriter {
    fn block_size(&self) -> LengthType;
    fn read_multi_blocks(
        &mut self,
        buffer: &mut [u8],
        start_block_num: OffsetType,
        end_block_num: OffsetType,
    ) -> Result<LengthType, Box<dyn Error>>;
    fn write_multi_blocks(
        &mut self,
        buffer: &[u8],
        start_block_num: OffsetType,
        end_block_num: OffsetType,
        end_residue: OffsetType,
    ) -> Result<(), Box<dyn Error>>;
    fn adjust_logical_size(&mut self, length: LengthType) -> Result<(), Box<dyn Error>>;
    fn size(&self) -> Result<LengthType, Box<dyn Error>>;
    fn flush(&mut self) -> Result<(), Box<dyn Error>>;
}

fn divmod<T: Div<Output = T> + Rem<Output = T> + Copy>(x: T, y: T) -> (T, T) {
    (x / y, x % y)
}

impl<T: MultipleBlockReaderWriter> Stream for T {
    fn read(
        &mut self,
        buffer: &mut [u8],
        offset: OffsetType,
    ) -> Result<LengthType, Box<dyn Error>> {
        if buffer.is_empty() {
            return Ok(0);
        }

        let (start_block, start_residue) = divmod(offset, self.block_size());
        let (end_block, end_residue) = divmod(
            offset + TryInto::<OffsetType>::try_into(buffer.len())?,
            self.block_size(),
        );

        if start_residue == 0 && end_residue == 0 {
            return self.read_multi_blocks(buffer, start_block, end_block);
        }

        let mut temp_buffer = vec![
            0u8;
            ((end_block - start_block + if end_residue > 0 { 1 } else { 0 })
                * self.block_size())
            .try_into()?
        ];
        let read_len = self.read_multi_blocks(
            &mut temp_buffer,
            start_block,
            end_block + if end_residue > 0 { 1 } else { 0 },
        )?;

        if read_len <= start_residue {
            return Ok(0);
        }

        let copy_len = std::cmp::min(read_len - start_residue, buffer.len().try_into()?);
        buffer[..copy_len.try_into()?].copy_from_slice(
            &temp_buffer[start_residue.try_into()?..(start_residue + copy_len).try_into()?],
        );
        Ok(copy_len)
    }

    fn write(&mut self, buffer: &[u8], offset: OffsetType) -> Result<(), Box<dyn Error>> {
        if buffer.is_empty() {
            return Ok(());
        }
        let current_size = self.size()?;
        if offset > current_size {
            self.resize(offset)?;
        }
        self.unchecked_write(buffer, offset)
    }

    fn size(&self) -> Result<LengthType, Box<dyn Error>> {
        self.size()
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        self.flush()
    }

    fn resize(&mut self, size: LengthType) -> Result<(), Box<dyn Error>> {
        let current_size = self.size()?;
        if size == current_size {
            return Ok(());
        } else if size < current_size {
            let residue: u64 = size % self.block_size();
            let block_num = size / self.block_size();
            if residue > 0 {
                let mut temp_buffer = vec![0; self.block_size().try_into()?];
                self.read_multi_blocks(&mut temp_buffer, block_num, block_num + 1)?;
                self.write_multi_blocks(&temp_buffer, block_num, block_num, residue)?;
            }
        } else {
            let old_block_num = current_size / self.block_size();
            let new_block_num = size / self.block_size();
            if !self.is_sparse() || old_block_num == new_block_num {
                self.zero_fill(current_size, size)?;
            } else {
                self.zero_fill(
                    current_size,
                    old_block_num * self.block_size() + self.block_size(),
                )?;
            }
        }
        self.adjust_logical_size(size)
    }
}

trait UncheckedWriter {
    fn unchecked_write(&mut self, buffer: &[u8], offset: OffsetType) -> Result<(), Box<dyn Error>>;
    fn zero_fill(&mut self, offset: OffsetType, size: LengthType) -> Result<(), Box<dyn Error>>;
}

impl<T: MultipleBlockReaderWriter> UncheckedWriter for T {
    fn unchecked_write(&mut self, buffer: &[u8], offset: OffsetType) -> Result<(), Box<dyn Error>> {
        if buffer.is_empty() {
            return Ok(());
        }
        let (start_block, start_residue) = divmod(offset, self.block_size());
        let (end_block, end_residue) = divmod(
            offset + TryInto::<OffsetType>::try_into(buffer.len())?,
            self.block_size(),
        );

        if start_residue == 0 && end_residue == 0 {
            return self.write_multi_blocks(buffer, start_block, end_block, 0);
        }

        let mut temp_buffer = vec![
            0u8;
            ((end_block - start_block + if end_residue > 0 { 1 } else { 0 })
                * self.block_size())
            .try_into()?
        ];

        if start_residue > 0 && start_block < end_block {
            self.read_multi_blocks(
                &mut temp_buffer[..self.block_size().try_into()?],
                start_block,
                start_block + 1,
            )?;
        }

        let mut effective_end_residue = 0;
        if end_residue > 0 {
            effective_end_residue = std::cmp::max(
                end_residue,
                self.read_multi_blocks(
                    &mut temp_buffer
                        [((end_block - start_block) * self.block_size()).try_into()?..],
                    end_block,
                    end_block + 1,
                )?,
            );
        }

        let buflen: OffsetType = buffer.len().try_into()?;
        temp_buffer[start_residue.try_into()?..(start_residue + buflen).try_into()?]
            .copy_from_slice(buffer);
        self.write_multi_blocks(&temp_buffer, start_block, end_block, effective_end_residue)
    }

    fn zero_fill(&mut self, offset: OffsetType, size: LengthType) -> Result<(), Box<dyn Error>> {
        let buffer = vec![0u8; (size - offset).try_into()?];
        self.unchecked_write(&buffer, offset)
    }
}
