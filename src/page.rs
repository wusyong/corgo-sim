use core::{mem::size_of, ptr::null_mut};

extern "C" {
    static HEAP_START: usize;
    static HEAP_SIZE: usize;
}

static mut ALLOC_START: usize = 0;
const PAGE_ORDER: usize = 12;
pub const PAGE_SIZE: usize = 1 << 12;

pub const fn align_val(val: usize, order: usize) -> usize {
    let o = (1usize << order) - 1;
    (val + o) & !o
}

#[repr(u8)]
pub enum PageBits {
    Empty = 0,
    Taken = 1 << 0,
    Last = 1 << 1,
}

impl PageBits {
    pub fn val(self) -> u8 {
        self as u8
    }
}

pub struct Page {
    flags: u8,
}

impl Page {
    pub fn is_last(&self) -> bool {
        if self.flags & PageBits::Last.val() != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_taken(&self) -> bool {
        if self.flags & PageBits::Taken.val() != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_free(&self) -> bool {
        !self.is_taken()
    }

    pub fn clear(&mut self) {
        self.flags = PageBits::Empty.val();
    }

    pub fn set_flag(&mut self, flag: PageBits) {
        self.flags |= flag.val();
    }

    pub fn clear_flag(&mut self, flag: PageBits) {
        self.flags &= !(flag.val());
    }
}

pub fn init() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        
        for i in 0..num_pages {
            (*ptr.add(i)).clear();
        }

        ALLOC_START = align_val(HEAP_START + num_pages * size_of::<Page>(), PAGE_ORDER);
    }
}

pub fn alloc(pages: usize) -> *mut u8 {
    assert!(pages > 0);
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        for i in 0..num_pages - pages {
            let mut found = false;
            if (*ptr.add(i)).is_free() {
                found = true;
                for j in i..i + pages {
                    if (*ptr.add(j)).is_taken() {
                        found = false;
                        break;
                    }
                }
            }

            if found {
                for k in i..i + pages - 1 {
                    (*ptr.add(k)).set_flag(PageBits::Taken);
                }
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Taken);
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Last);
                return (ALLOC_START + PAGE_SIZE * i) as *mut u8;
            }
        }
    }

    null_mut()
}

pub fn zalloc(pages: usize) -> *mut u8 {
    let ret = alloc(pages);
    if !ret.is_null() {
        let size = (PAGE_SIZE * pages) / 8;
        let big_ptr = ret as *mut u64;
        for i in 0..size {
            unsafe {
                (*big_ptr.add(i)) = 0;
            }
        }
    }
    ret
}

pub fn dealloc(ptr: *mut u8) {
    assert!(!ptr.is_null());
    unsafe {
        let addr = HEAP_START + (ptr as usize - ALLOC_START) / PAGE_SIZE;
        assert!(addr >= HEAP_START && addr < HEAP_START + HEAP_SIZE);
        let mut p = addr as *mut Page;
        while (*p).is_taken() && !(*p).is_last() {
            (*p).clear();
            p = p.add(1);
        }
        assert!(
            (*p).is_last() == true,
            "Possible double-free detected! (Not taken found \
		         before last)"
        );
        (*p).clear();
    }
}

pub fn print_page_allocations() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let mut beg = HEAP_START as *const Page;
        let end = beg.add(num_pages);
        let alloc_beg = ALLOC_START;
        let alloc_end = ALLOC_START + num_pages * PAGE_SIZE;
        println!();
        println!(
            "PAGE ALLOCATION TABLE\nMETA: {:p} -> {:p}\nPHYS: \
		          0x{:x} -> 0x{:x}",
            beg, end, alloc_beg, alloc_end
        );
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        let mut num = 0;
        while beg < end {
            if (*beg).is_taken() {
                let start = beg as usize;
                let memaddr = ALLOC_START + (start - HEAP_START) * PAGE_SIZE;
                print!("0x{:x} => ", memaddr);
                loop {
                    num += 1;
                    if (*beg).is_last() {
                        let end = beg as usize;
                        let memaddr = ALLOC_START + (end - HEAP_START) * PAGE_SIZE + PAGE_SIZE - 1;
                        print!("0x{:x}: {:>3} page(s)", memaddr, (end - start + 1));
                        println!(".");
                        break;
                    }
                    beg = beg.add(1);
                }
            }
            beg = beg.add(1);
        }
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        println!(
            "Allocated: {:>5} pages ({:>9} bytes).",
            num,
            num * PAGE_SIZE
        );
        println!(
            "Free     : {:>5} pages ({:>9} bytes).",
            num_pages - num,
            (num_pages - num) * PAGE_SIZE
        );
        println!();
    }
}

// ////////////////////////////////
// // MMU Routines
// ////////////////////////////////

// Represent (repr) our entry bits as
// unsigned 64-bit integers.
#[repr(i64)]
#[derive(Copy, Clone)]
pub enum EntryBits {
    None = 0,
    Valid = 1 << 0,
    Read = 1 << 1,
    Write = 1 << 2,
    Execute = 1 << 3,
    User = 1 << 4,
    Global = 1 << 5,
    Access = 1 << 6,
    Dirty = 1 << 7,

    // Convenience combinations
    ReadWrite = 1 << 1 | 1 << 2,
    ReadExecute = 1 << 1 | 1 << 3,
    ReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3,

    // User Convenience Combinations
    UserReadWrite = 1 << 1 | 1 << 2 | 1 << 4,
    UserReadExecute = 1 << 1 | 1 << 3 | 1 << 4,
    UserReadWriteExecute = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4,
}

// Helper functions to convert the enumeration
// into an i64, which is what our page table
// entries will be.
impl EntryBits {
    pub fn val(self) -> i64 {
        self as i64
    }
}

// A single entry. We're using an i64 so that
// this will sign-extend rather than zero-extend
// since RISC-V requires that the reserved sections
// take on the most significant bit.
pub struct Entry {
    pub entry: i64,
}

// The Entry structure describes one of the 512 entries per table, which is
// described in the RISC-V privileged spec Figure 4.18.
impl Entry {
    pub fn is_valid(&self) -> bool {
        self.get_entry() & EntryBits::Valid.val() != 0
    }

    // The first bit (bit index #0) is the V bit for
    // valid.
    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }

    // A leaf has one or more RWX bits set
    pub fn is_leaf(&self) -> bool {
        self.get_entry() & 0xe != 0
    }

    pub fn is_branch(&self) -> bool {
        !self.is_leaf()
    }

    pub fn set_entry(&mut self, entry: i64) {
        self.entry = entry;
    }

    pub fn get_entry(&self) -> i64 {
        self.entry
    }
}

// Table represents a single table, which contains 512 (2^9), 64-bit entries.
pub struct Table {
    pub entries: [Entry; 512],
}

impl Table {
    pub fn len() -> usize {
        512
    }
}

/// Map a virtual address to a physical address using 4096-byte page
/// size.
/// root: a mutable reference to the root Table
/// vaddr: The virtual address to map
/// paddr: The physical address to map
/// bits: An OR'd bitset containing the bits the leaf should have.
///       The bits should contain only the following:
///          Read, Write, Execute, User, and/or Global
///       The bits MUST include one or more of the following:
///          Read, Write, Execute
///       The valid bit automatically gets added.
pub fn map(root: &mut Table, vaddr: usize, paddr: usize, bits: i64, level: usize) {
    // Make sure that Read, Write, or Execute have been provided
    // otherwise, we'll leak memory and always create a page fault.
    assert!(bits & 0xe != 0);
    // Extract out each VPN from the virtual address
    // On the virtual address, each VPN is exactly 9 bits,
    // which is why we use the mask 0x1ff = 0b1_1111_1111 (9 bits)
    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];

    // Just like the virtual address, extract the physical address
    // numbers (PPN). However, PPN[2] is different in that it stores
    // 26 bits instead of 9. Therefore, we use,
    // 0x3ff_ffff = 0b11_1111_1111_1111_1111_1111_1111 (26 bits).
    let ppn = [
        // PPN[0] = paddr[20:12]
        (paddr >> 12) & 0x1ff,
        // PPN[1] = paddr[29:21]
        (paddr >> 21) & 0x1ff,
        // PPN[2] = paddr[55:30]
        (paddr >> 30) & 0x3ff_ffff,
    ];
    // We will use this as a floating reference so that we can set
    // individual entries as we walk the table.
    let mut v = &mut root.entries[vpn[2]];
    // Now, we're going to traverse the page table and set the bits
    // properly. We expect the root to be valid, however we're required to
    // create anything beyond the root.
    // In Rust, we create a range iterator using the .. operator.
    // The .rev() will reverse the iteration since we need to start with
    // VPN[2] The .. operator is inclusive on start but exclusive on end.
    // So, (0..2) will iterate 0 and 1.
    for i in (level..2).rev() {
        if !v.is_valid() {
            // Allocate a page
            let page = zalloc(1);
            // The page is already aligned by 4,096, so store it
            // directly The page is stored in the entry shifted
            // right by 2 places.
            v.set_entry((page as i64 >> 2) | EntryBits::Valid.val());
        }
        let entry = ((v.get_entry() & !0x3ff) << 2) as *mut Entry;
        v = unsafe { entry.add(vpn[i]).as_mut().unwrap() };
    }
    // When we get here, we should be at VPN[0] and v should be pointing to
    // our entry.
    // The entry structure is Figure 4.18 in the RISC-V Privileged
    // Specification
    let entry = (ppn[2] << 28) as i64 |   // PPN[2] = [53:28]
	            (ppn[1] << 19) as i64 |   // PPN[1] = [27:19]
				(ppn[0] << 10) as i64 |   // PPN[0] = [18:10]
				bits |                    // Specified bits, such as User, Read, Write, etc
				EntryBits::Valid.val(); // Valid bit
                        // Set the entry. V should be set to the correct pointer by the loop
                        // above.
    v.set_entry(entry);
}

/// Unmaps and frees all memory associated with a table.
/// root: The root table to start freeing.
/// NOTE: This does NOT free root directly. This must be
/// freed manually.
/// The reason we don't free the root is because it is
/// usually embedded into the Process structure.
pub fn unmap(root: &mut Table) {
    // Start with level 2
    for lv2 in 0..Table::len() {
        let ref entry_lv2 = root.entries[lv2];
        if entry_lv2.is_valid() && entry_lv2.is_branch() {
            // This is a valid entry, so drill down and free.
            let memaddr_lv1 = (entry_lv2.get_entry() & !0x3ff) << 2;
            let table_lv1 = unsafe {
                // Make table_lv1 a mutable reference instead of a pointer.
                (memaddr_lv1 as *mut Table).as_mut().unwrap()
            };
            for lv1 in 0..Table::len() {
                let ref entry_lv1 = table_lv1.entries[lv1];
                if entry_lv1.is_valid() && entry_lv1.is_branch() {
                    let memaddr_lv0 = (entry_lv1.get_entry() & !0x3ff) << 2;
                    // The next level is level 0, which
                    // cannot have branches, therefore,
                    // we free here.
                    dealloc(memaddr_lv0 as *mut u8);
                }
            }
            dealloc(memaddr_lv1 as *mut u8);
        }
    }
}

/// Walk the page table to convert a virtual address to a
/// physical address.
/// If a page fault would occur, this returns None
/// Otherwise, it returns Some with the physical address.
pub fn virt_to_phys(root: &Table, vaddr: usize) -> Option<usize> {
    // Walk the page table pointed to by root
    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];

    let mut v = &root.entries[vpn[2]];
    for i in (0..=2).rev() {
        if v.is_invalid() {
            // This is an invalid entry, page fault.
            break;
        } else if v.is_leaf() {
            // According to RISC-V, a leaf can be at any level.

            // The offset mask masks off the PPN. Each PPN is 9
            // bits and they start at bit #12. So, our formula
            // 12 + i * 9
            let off_mask = (1 << (12 + i * 9)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.get_entry() << 2) as usize) & !off_mask;
            return Some(addr | vaddr_pgoff);
        }
        // Set v to the next entry which is pointed to by this
        // entry. However, the address was shifted right by 2 places
        // when stored in the page table entry, so we shift it left
        // to get it back into place.
        let entry = ((v.get_entry() & !0x3ff) << 2) as *const Entry;
        // We do i - 1 here, however we should get None or Some() above
        // before we do 0 - 1 = -1.
        v = unsafe { entry.add(vpn[i - 1]).as_ref().unwrap() };
    }

    // If we get here, we've exhausted all valid tables and haven't
    // found a leaf.
    None
}
