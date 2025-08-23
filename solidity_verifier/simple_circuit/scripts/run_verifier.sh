#!/bin/bash

echo "Building Solidity verifier..."
forge build

echo "Running Solidity verifier tests..."
forge test --gas-report 2>&1 | tee solidity_verifier_test.log

echo "Tests completed. Check solidity_verifier_test.log for detailed output." 