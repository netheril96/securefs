use std::{cmp::min, usize};

type OffsetType = u64;
type LengthType = u64;

trait Stream {
    fn read(
        &mut self,
        buffer: &mut [u8],
        offset: OffsetType,
    ) -> Result<LengthType, Box<dyn std::error::Error>>;
    fn write(
        &mut self,
        buffer: &[u8],
        offset: OffsetType,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn size(&self) -> Result<LengthType, Box<dyn std::error::Error>>;
    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>>;
    fn resize(&mut self, size: LengthType) -> Result<(), Box<dyn std::error::Error>>;
    fn is_sparse(&self) -> bool {
        false
    }
    fn optimal_block_size(&self) -> LengthType {
        1
    }
}

pub struct MemoryStream {
    buffer: Vec<u8>,
}

impl Stream for MemoryStream {
    fn read(
        &mut self,
        buffer: &mut [u8],
        offset: OffsetType,
    ) -> Result<LengthType, Box<dyn std::error::Error>> {
        if offset >= self.buffer.len().try_into()? {
            return Ok(0);
        }
        let slice = &self.buffer
            [offset.try_into()?..min(offset as usize + buffer.len(), self.buffer.len())];
        let (to_be_copied, _) = buffer.split_at_mut(slice.len());
        to_be_copied.copy_from_slice(slice);
        Ok(slice.len().try_into()?)
    }

    fn write(
        &mut self,
        buffer: &[u8],
        offset: OffsetType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let end: u64 = offset + TryInto::<u64>::try_into(buffer.len())?;
        if end > self.buffer.len().try_into()? {
            self.buffer.resize(end.try_into()?, 0);
        }
        let slice = &mut self.buffer[offset.try_into()?..end.try_into()?];
        slice.copy_from_slice(buffer);
        Ok(())
    }

    fn size(&self) -> Result<LengthType, Box<dyn std::error::Error>> {
        Ok(self.buffer.len().try_into()?)
    }

    fn flush(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn resize(&mut self, size: LengthType) -> Result<(), Box<dyn std::error::Error>> {
        self.buffer.resize(size.try_into()?, 0);
        Ok(())
    }
}
