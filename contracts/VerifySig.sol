/**
 * @description       : Verify web3 signatures from signed messages and retrieve the public key
 * @author            : Damien Fleminks
 * @Co-Author         : Used code examples from:  https://solidity-by-example.org/signature/ 
 * @last modified on  : 03-23-2022
 * @last modified by  : Damien Fleminks
**/
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract VerifySig {

    /**
        Get wallet address by the message and 
     */
    function recoverSigner(string memory _message, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(hashMessage(_message), v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */


            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }



    function hashMessage(string memory _message)
        private
        pure
        returns (bytes32)
    {
        /** Return keccak256 hashed ethereum compatible message sha, assuming 32 characters _message string  **/
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",_message));
    }


    


  
}
