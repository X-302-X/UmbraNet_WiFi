//! Разбор событий WinDivert REFLECT 2.2. Не устанавливает принадлежность PID.
#[repr(C)]
pub(super) struct ReflectAddress {
    pub timestamp: i64,
    pub bits: u32,
    pub reserved: u32,
    pub data: [u8; 64],
}
impl Default for ReflectAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

pub(super) fn decode(addr: &ReflectAddress) -> Option<(u32, u32)> {
    const REFLECT_LAYER: u32 = 4;
    const REFLECT_OPEN: u32 = 8;
    if (addr.bits & 0xff) != REFLECT_LAYER || ((addr.bits >> 8) & 0xff) != REFLECT_OPEN {
        return None;
    }
    let pid = u32::from_le_bytes(addr.data[8..12].try_into().ok()?);
    let layer = u32::from_le_bytes(addr.data[12..16].try_into().ok()?);
    if pid == 0 || layer > 4 {
        return None;
    }
    Some((pid, layer))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_and_open_event_are_checked() {
        assert_eq!(std::mem::size_of::<ReflectAddress>(), 80);
        assert_eq!(std::mem::offset_of!(ReflectAddress, data), 16);
        let mut a = ReflectAddress {
            bits: 4 | (8 << 8),
            ..Default::default()
        };
        a.data[8..12].copy_from_slice(&42u32.to_le_bytes());
        a.data[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(decode(&a), Some((42, 2)));
        a.bits = 4 | (9 << 8);
        assert_eq!(decode(&a), None);
        a.bits = 4 | (8 << 8);
        a.data[8..12].fill(0);
        assert_eq!(decode(&a), None);
        a.data[8..12].copy_from_slice(&42u32.to_le_bytes());
        a.data[12..16].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(decode(&a), None);
    }
}
