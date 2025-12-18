#!/bin/bash

echo "========================================"
echo "   Cassandra Ransomware Launcher"
echo "========================================"
echo
echo "Choose an option:"
echo
echo "1. Safe Demo Mode (Recommended)"
echo "2. Show Help"
echo "3. Developer Test Mode"
echo "4. Integration Test"
echo "5. Full Execution (DANGER!)"
echo
read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo
        echo "Starting Safe Demo Mode..."
        cargo run -- --demo
        ;;
    2)
        echo
        echo "Showing Help..."
        cargo run -- --help
        ;;
    3)
        echo
        echo "Starting Developer Test Mode..."
        cargo run -- test
        ;;
    4)
        echo
        echo "Starting Integration Test..."
        cargo run -- integration
        ;;
    5)
        echo
        echo "========================================"
        echo "        ⚠️  EXTREME WARNING ⚠️"
        echo "========================================"
        echo
        echo "You are about to run the FULL RANSOMWARE!"
        echo "This will ENCRYPT files on your system!"
        echo
        echo "This is EXTREMELY DANGEROUS!"
        echo "Only run in isolated VMs for research!"
        echo
        read -p "Type 'YES' to confirm: " confirm
        if [ "$confirm" != "YES" ]; then
            echo "Operation cancelled."
            exit 1
        fi
        echo
        echo "Starting FULL EXECUTION in 5 seconds..."
        sleep 5
        cargo run
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

echo
echo "Operation completed."