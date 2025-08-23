// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/Verifier.sol";

contract SimpleCircuitVerifierTest is Test {
    HonkVerifier public verifier;
    bytes public proof;
    bytes public vk;
    bytes public publicInputs;

    function setUp() public {
        verifier = new HonkVerifier();
        
        // Read binary files
        proof = vm.readFileBinary("src/proof");
        vk = vm.readFileBinary("src/vk");
        publicInputs = vm.readFileBinary("src/public_inputs");
        
        console.log("Proof size:", proof.length);
        console.log("VK size:", vk.length);
        console.log("Public inputs size:", publicInputs.length);
    }

    function testVerifyProof() public {
        bytes32[] memory publicInputsArray = convertToBytes32Array(publicInputs);
        
        console.log("Public inputs array length:", publicInputsArray.length);
        console.log("First public input:", uint256(publicInputsArray[0]));
        
        bool isValid = verifier.verify(proof, publicInputsArray);
        console.log("Verification result:", isValid);
        
        assertTrue(isValid, "Proof verification should succeed");
    }

    function testProofStructure() public {
        console.log("=== Proof Structure Analysis ===");
        console.log("Total proof size:", proof.length, "bytes");
        
        // Analyze proof in 32-byte sections
        uint256 sections = proof.length / 32;
        console.log("Number of 32-byte sections:", sections);
        
        // Copy storage variables to local variables for assembly
        bytes memory proofBytes = proof;
        
        for (uint256 i = 0; i < sections && i < 10; i++) {
            bytes32 section;
            assembly {
                section := mload(add(proofBytes, add(32, mul(i, 32))))
            }
            console.log("Section", i, ":", uint256(section));
        }
    }

    function testPublicInputsAnalysis() public {
        console.log("=== Public Inputs Analysis ===");
        console.log("Public inputs size:", publicInputs.length, "bytes");
        
        if (publicInputs.length >= 32) {
            // Copy storage variables to local variables for assembly
            bytes memory publicInputsBytes = publicInputs;
            bytes32 firstInput;
            assembly {
                firstInput := mload(add(publicInputsBytes, 32))
            }
            console.log("First 32 bytes as uint256:", uint256(firstInput));
        }
    }

    function logProofDetails() public {
        console.log("=== Proof Details ===");
        
        // Copy storage variables to local variables for assembly
        bytes memory proofBytes = proof;
        bytes memory publicInputsBytes = publicInputs;
        bytes memory vkBytes = vk;
        
        if (proofBytes.length >= 32) {
            bytes32 proofFirst;
            assembly {
                proofFirst := mload(add(proofBytes, 32))
            }
            console.log("Proof (first 32 bytes):", uint256(proofFirst));
        }
        
        if (publicInputsBytes.length >= 32) {
            bytes32 inputsFirst;
            assembly {
                inputsFirst := mload(add(publicInputsBytes, 32))
            }
            console.log("Public inputs:", uint256(inputsFirst));
        }
        
        if (vkBytes.length >= 32) {
            bytes32 vkFirst;
            assembly {
                vkFirst := mload(add(vkBytes, 32))
            }
            console.log("VK (first 32 bytes):", uint256(vkFirst));
        }
    }

    function convertToBytes32Array(bytes memory input) internal pure returns (bytes32[] memory) {
        require(input.length % 32 == 0, "Input length must be multiple of 32");
        
        uint256 numElements = input.length / 32;
        bytes32[] memory result = new bytes32[](numElements);
        
        for (uint256 i = 0; i < numElements; i++) {
            bytes32 element;
            assembly {
                element := mload(add(input, add(32, mul(i, 32))))
            }
            result[i] = element;
        }
        
        return result;
    }
} 