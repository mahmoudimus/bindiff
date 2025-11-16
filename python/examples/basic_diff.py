#!/usr/bin/env python3
"""
Basic BinDiff Example

Demonstrates how to perform a basic binary diff using the Python interface.
"""

import sys
from pathlib import Path

import bindiff


def main():
    if len(sys.argv) != 4:
        print("Usage: basic_diff.py <primary.BinExport> <secondary.BinExport> <output.db>")
        print()
        print("Example:")
        print("  basic_diff.py old_version.BinExport new_version.BinExport diff_results.db")
        sys.exit(1)

    primary = sys.argv[1]
    secondary = sys.argv[2]
    output = sys.argv[3]

    # Validate input files exist
    if not Path(primary).exists():
        print(f"Error: Primary file not found: {primary}")
        sys.exit(1)

    if not Path(secondary).exists():
        print(f"Error: Secondary file not found: {secondary}")
        sys.exit(1)

    print("BinDiff - Binary Comparison Tool")
    print("=" * 60)
    print(f"Primary:   {primary}")
    print(f"Secondary: {secondary}")
    print(f"Output:    {output}")
    print()

    # Perform diff
    print("Performing diff...")
    result = bindiff.diff(primary, secondary, output)

    if result != 0:
        print(f"Error: Diff failed with code {result}")
        error_messages = {
            -1: "Failed to read primary binary",
            -2: "Failed to read secondary binary",
            -3: "Failed to create output database",
            -4: "Failed to write results",
            -99: "Unexpected error occurred",
        }
        print(error_messages.get(result, "Unknown error"))
        sys.exit(1)

    print("Diff completed successfully!")
    print()

    # Load and display results
    print("Loading results...")
    results = bindiff.Results.load(output)

    # Print summary
    results.print_summary()

    # Show top matches
    print("\nTop 10 Matches by Similarity:")
    print("-" * 60)
    for i, match in enumerate(results.matches[:10], 1):
        print(f"{i:2}. {match.primary_name}")
        print(f"    -> {match.secondary_name}")
        print(f"    Similarity: {match.similarity:5.1%}  Confidence: {match.confidence:5.1%}")
        print()

    # Show match distribution
    similarity_ranges = [
        (1.0, 1.0, "Perfect"),
        (0.9, 0.99, "Very High"),
        (0.7, 0.89, "High"),
        (0.5, 0.69, "Medium"),
        (0.0, 0.49, "Low"),
    ]

    print("Match Distribution by Similarity:")
    print("-" * 60)
    for min_sim, max_sim, label in similarity_ranges:
        matches_in_range = results.get_matches_by_similarity(min_sim, max_sim)
        count = len(matches_in_range)
        if count > 0:
            pct = (count / results.num_matches) * 100
            print(f"{label:12} ({min_sim:.0%}-{max_sim:.0%}): {count:5} ({pct:5.1f}%)")

    print()
    print("Analysis complete!")


if __name__ == "__main__":
    main()
