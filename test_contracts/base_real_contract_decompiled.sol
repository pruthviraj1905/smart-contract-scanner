// Real Base Contract - Decompiled by library.dedaub.com
// Address: 0x0619a9d474fdbc343b0c84488bec3a15733f4e38
// 2025.10.14 21:55 UTC
// Compiled using the solidity compiler version 0.8.26

// Data structures and variables inferred from the use of storage instructions
address ___function_selector__; // STORAGE[0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc] bytes 0 to 19

// Events
Upgraded(address);

// Note: The function selector is not present in the original solidity code.
// However, we display it for the sake of completeness.

function __function_selector__(bytes4 function_selector, address varg1, uint256 varg2) public payable { 
    if (address(0xd33b78c01482587b4e43d6a85cbc79243c6f140e) - msg.sender) {
        CALLDATACOPY(0, 0, msg.data.length);
        v0 = ___function_selector__.delegatecall(MEM[0:msg.data.length], MEM[0:0]).gas(msg.gas);
        require(v0, 0, RETURNDATASIZE()); // checks call status, propagates error data on error
        return MEM[0:RETURNDATASIZE()];
    } else {
        require(0x4f1ef28600000000000000000000000000000000000000000000000000000000 == function_selector, ProxyDeniedAdminAccess());
        require(4 <= msg.data.length);
        require(msg.data.length - 4 >= 64);
        require(varg2 <= uint64.max);
        require(varg2 + 35 < msg.data.length);
        require(varg2.length <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
        v1 = new bytes[](varg2.length);
        require(!((v1 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 31 + varg2.length)) < v1) | (v1 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 31 + varg2.length)) > uint64.max)), Panic(65)); // failed memory allocation (too much memory)
        require(varg2 + varg2.length + 36 <= msg.data.length);
        CALLDATACOPY(v1.data, varg2.data, varg2.length);
        v1[varg2.length] = 0;
        require(varg1.code.size, ERC1967InvalidImplementation(varg1));
        ___function_selector__ = varg1;
        emit Upgraded(varg1);
        if (!v1.length) {
            require(!msg.value, ERC1967NonPayable());
        } else {
            v2, /* uint256 */ v3 = varg1.delegatecall(MEM[vcfV0xe80V0x5f.data:vcfV0xe80V0x5f.data + vcfV0xe80V0x5f.length], MEM[0:0]).gas(msg.gas);
            if (!RETURNDATASIZE()) {
                v4 = v5 = 96;
            } else {
                require(RETURNDATASIZE() <= uint64.max, Panic(65)); // failed memory allocation (too much memory)
                v4 = new bytes[](RETURNDATASIZE());
                require(!((v4 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 31 + RETURNDATASIZE())) < v4) | (v4 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 63 + (0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0 & 31 + RETURNDATASIZE())) > uint64.max)), Panic(65)); // failed memory allocation (too much memory)
                v3 = v4.data;
                RETURNDATACOPY(v3, 0, RETURNDATASIZE());
            }
            if (v2) {
                v6 = v7 = !MEM[v4];
                if (v7) {
                    v6 = v8 = !varg1.code.size;
                }
                require(!v6, AddressEmptyCode(varg1));
            } else {
                require(!MEM[v4], 32 + v4, MEM[v4]);
                revert(FailedInnerCall());
            }
        }
        exit;
    }
}