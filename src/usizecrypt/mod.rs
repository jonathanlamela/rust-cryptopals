use rand::RngCore;

pub trait USizeCrypt {
    fn random_block(self) -> Vec<u8>;
    fn chunks_count(self) -> (usize, usize);
}

impl USizeCrypt for usize {
    //Create a random block of bytes starting from the usize instance value
    fn random_block(self) -> Vec<u8> {
        let mut key = vec![0u8; self];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);

        key
    }

    // The first value indicates the number of 'chunks', the second how many bytes need to be added to the usize value to make it a multiple of 16
    fn chunks_count(self) -> (usize, usize) {
        let q = (self + 16 - 1) / 16;
        let r = q * 16 - self;
        (q, r)
    }
}
