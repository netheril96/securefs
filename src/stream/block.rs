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
    fn is_sparse(&self) -> bool {
        false
    }
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
            let (block_num, residue) = divmod(size, self.block_size());
            if residue > 0 {
                let mut temp_buffer: Vec<u8> = vec![0; self.block_size().try_into()?];
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

    fn is_sparse(&self) -> bool {
        self.is_sparse()
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

#[cfg(test)]
mod test {
    use crate::stream::{MemoryStream, test::compare_with_reference};

    use super::*;

    struct DummyBlockReaderWriter {
        data: Vec<Vec<u8>>,
        block_size: LengthType,
    }

    impl DummyBlockReaderWriter {
        const BLOCK_SIZE: LengthType = 1000;

        fn new() -> Self {
            Self {
                data: Vec::new(),
                block_size: Self::BLOCK_SIZE,
            }
        }
    }

    impl MultipleBlockReaderWriter for DummyBlockReaderWriter {
        fn block_size(&self) -> LengthType {
            self.block_size
        }

        fn read_multi_blocks(
            &mut self,
            buffer: &mut [u8],
            start_block_num: OffsetType,
            end_block_num: OffsetType,
        ) -> Result<LengthType, Box<dyn Error>> {
            let mut result: LengthType = 0;
            let mut output_offset: OffsetType = 0;
            for block_num in start_block_num..end_block_num {
                if block_num >= self.data.len().try_into()? {
                    return Ok(result);
                }
                let block: &[u8] = &self.data[TryInto::<usize>::try_into(block_num)?];
                let block_len: OffsetType = block.len().try_into()?;
                buffer[output_offset.try_into()?..(output_offset + block_len).try_into()?]
                    .copy_from_slice(block);
                result += block_len;
                output_offset += block_len;
            }
            Ok(result)
        }

        fn write_multi_blocks(
            &mut self,
            buffer: &[u8],
            start_block_num: OffsetType,
            end_block_num: OffsetType,
            end_residue: OffsetType,
        ) -> Result<(), Box<dyn Error>> {
            let block_size: usize = self.block_size.try_into()?;

            if self.data.len() < end_block_num.try_into()? {
                self.data
                    .resize_with(end_block_num.try_into()?, || vec![0; block_size]);
            }

            let mut input_offset = 0;
            for block_num in start_block_num..end_block_num {
                let block: &mut Vec<u8> = &mut self.data[TryInto::<usize>::try_into(block_num)?];
                block.resize(block_size, 0);
                block.copy_from_slice(&buffer[input_offset..input_offset + block_size]);
                input_offset += block_size;
            }

            if end_residue > 0 {
                if self.data.len() <= end_block_num.try_into()? {
                    self.data.push(Vec::new());
                }
                let block = &mut self.data[TryInto::<usize>::try_into(end_block_num)?];
                if block.len() < end_residue.try_into()? {
                    block.resize(end_residue.try_into()?, 0);
                }
                block[..end_residue.try_into()?].copy_from_slice(
                    &buffer[input_offset..input_offset + TryInto::<usize>::try_into(end_residue)?],
                );
            }
            Ok(())
        }

        fn adjust_logical_size(&mut self, length: LengthType) -> Result<(), Box<dyn Error>> {
            let block_size: usize = self.block_size.try_into()?;

            if length == 0 {
                self.data.clear();
                return Ok(());
            }
            let num_blocks = (length + (self.block_size - 1)) / self.block_size;
            let residue = length % self.block_size;

            self.data
                .resize_with(num_blocks.try_into()?, || vec![0; block_size]);

            if let Some(last_block) = self.data.last_mut() {
                last_block.resize(
                    (if residue == 0 {
                        self.block_size
                    } else {
                        residue
                    })
                    .try_into()?,
                    0,
                );
            }

            Ok(())
        }

        fn size(&self) -> Result<LengthType, Box<dyn Error>> {
            self.data
                .iter()
                .map(|it| TryInto::<LengthType>::try_into(it.len()))
                .try_fold(0, |acc, item| Ok(acc + item?))
        }

        fn flush(&mut self) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }

    #[test]
    fn test_dummy_block() {
        compare_with_reference(
            &mut DummyBlockReaderWriter::new(),
            &mut MemoryStream { buffer: Vec::new() },
            1000,
        )
        .unwrap();
    }
}
