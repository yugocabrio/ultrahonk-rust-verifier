# Simple Circuit Solidity Verifier

This Foundry project contains the Solidity verifier for the simple_circuit, generated from the Noir circuit compilation.

## Project Structure

- `src/Verifier.sol` - The generated Solidity verifier contract
- `src/proof` - Binary proof data
- `src/vk` - Verification key
- `src/public_inputs` - Public inputs for verification
- `test/SimpleCircuitVerifier.t.sol` - Test suite with detailed logging
- `scripts/run_verifier.sh` - Script to run tests and capture logs

## Usage

### Prerequisites
- Foundry (forge) installed
- Solidity 0.8.27

### Running Tests
```bash
# Run all tests with detailed logging
./scripts/run_verifier.sh

# Or manually
forge build
forge test --verbosity 5 --gas-report
```

### Test Functions
- `testVerifyProof()` - Main verification test
- `testProofStructure()` - Analyzes proof structure
- `testPublicInputsAnalysis()` - Analyzes public inputs
- `logProofDetails()` - Logs detailed proof information

## Configuration

The `foundry.toml` is configured for:
- High verbosity logging
- File system permissions for reading proof files
- Gas reporting
- Optimized compilation

## Purpose

This verifier is used to compare verification results with the Rust implementation to identify differences in MSM (Multi-Scalar Multiplication) calculations that cause the "Shplonk pairing check failed" error in the Rust verifier.
