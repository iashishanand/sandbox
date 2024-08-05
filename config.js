import bitcoin from "bitcoinjs-lib";

export const TESTNET = bitcoin.networks.testnet;

export const wallets = [
    {
        name: "alice",
        sec_key: "6ccc11c46751edab5d9ba2acf68d0133fb67b68fa701c2ab8eddd3d98efe5595",
        pub_key: "633d066237862db2292981e8b1e191c15b6a853a8083160076a24168f83a9d57",
        sec_nonce: "cab3a3a5bf918e75e6835a37e8988a99b90e15d32efa67a31c5992a1d449754462a3d3468cb0d14c1c3eb4c3c3743c29c821ea2e969fcb847cff6ab137f4555f",
        pub_nonce: "33fce8b07af2a03c9ea546c2c231cc8a5668cb28dc95290b3650fdaeaa1ef571e1cc83c729b3838fadc9dd3d6fecf58115e890974e0187d3c75f1ca52cb3759a",
    },
    {
        name: "bob",
        sec_key: "126086e85273e375ec6a059266c92f30ba070696334633624ace6a3bf5777f4b",
        pub_key: "d6be41e01c23fb2c57c1664c58998710f88174a41f1c69fd27be91518a5a84dd",
        sec_nonce: "28b75dc04532f69c64ac974eae8d43bd5db60b10410fc4838ae63f80a255108baafbcc53735b698dfce5f57bbbcce233fd9bc220470be343ea2b2b77e17c471f",
        pub_nonce: "95f5b0ebb638e5f0d374c17c7fb3d63126a20ffb2ef1b81c2c0afeee04c5e8dc016e291f06ebc7748c7f5e084fd8c12b655b602ebe5001e627334a225fa34350",
    },
];

export const utxo = {
    txid: "c08ca53cbf988a8c2d24a325e653683f5a183db7e580d0ea061c0250b903e7c5",
    vout: 1,
    value: 500000,
};

export const reciever = {
    value: 10000,
    address: "",
};
