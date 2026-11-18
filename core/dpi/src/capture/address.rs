//! ABI WINDIVERT_ADDRESS 2.2 на основе официального windivert.h.
//! Общая часть и 64-байтовый union имеют суммарный размер 80 байт на x64.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    bits: u32,
    reserved: u32,
    // Network-данные располагаются в начале 64-байтового union; u64 задаёт
    // требуемое выравнивание union по самому широкому члену на Windows x64.
    data: [u64; 8],
}

impl WinDivertAddress {
    const OUTBOUND: u32 = 1 << 17;
    const LOOPBACK: u32 = 1 << 18;
    const IMPOSTOR: u32 = 1 << 19;

    pub fn outbound(&self) -> bool {
        self.bits & Self::OUTBOUND != 0
    }
    pub fn loopback(&self) -> bool {
        self.bits & Self::LOOPBACK != 0
    }
    pub fn impostor(&self) -> bool {
        self.bits & Self::IMPOSTOR != 0
    }
    pub fn set_outbound(&mut self, value: bool) {
        if value {
            self.bits |= Self::OUTBOUND;
        } else {
            self.bits &= !Self::OUTBOUND;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn windivert_2_2_address_layout_matches_official_union() {
        assert_eq!(size_of::<WinDivertAddress>(), 80);
        assert_eq!(align_of::<WinDivertAddress>(), 8);
        assert_eq!(offset_of!(WinDivertAddress, timestamp), 0);
        assert_eq!(offset_of!(WinDivertAddress, bits), 8);
        assert_eq!(offset_of!(WinDivertAddress, reserved), 12);
        assert_eq!(offset_of!(WinDivertAddress, data), 16);
    }

    #[test]
    fn flags_do_not_confuse_sniffed_with_direction_and_preserve_other_bits() {
        let mut a = WinDivertAddress {
            bits: (1 << 16) | (1 << 18) | (1 << 19) | (1 << 22),
            ..Default::default()
        };
        assert!(!a.outbound());
        assert!(a.loopback());
        assert!(a.impostor());
        let original = a.bits;
        a.set_outbound(true);
        assert!(a.outbound());
        assert_eq!(a.bits, original | (1 << 17));
        a.set_outbound(false);
        assert_eq!(a.bits, original);
    }
}
