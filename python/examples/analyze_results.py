#!/usr/bin/env python3
"""
BinDiff Results Analyzer

Advanced analysis of BinDiff results including match filtering,
statistics calculation, and export capabilities.
"""

import sys
from pathlib import Path
from collections import defaultdict

import bindiff


def analyze_changes(results):
    """Analyze and categorize changes between binaries."""
    print("\nChange Analysis:")
    print("=" * 60)

    stats = results.statistics

    # Calculate change rates
    primary_changed = stats.primary_function_count - stats.matched_function_count
    secondary_changed = stats.secondary_function_count - stats.matched_function_count

    print(f"\nFunction Changes:")
    print(f"  Total Primary:      {stats.primary_function_count:6}")
    print(f"  Total Secondary:    {stats.secondary_function_count:6}")
    print(f"  Matched:            {stats.matched_function_count:6}")
    print(f"  Primary Only:       {primary_changed:6}")
    print(f"  Secondary Only:     {secondary_changed:6}")

    # Analyze match quality
    perfect_matches = len([m for m in results.matches if m.similarity >= 1.0])
    modified_matches = len([m for m in results.matches if m.similarity < 1.0])

    print(f"\nMatch Quality:")
    print(f"  Identical:          {perfect_matches:6} ({perfect_matches/stats.matched_function_count*100:.1f}%)")
    print(f"  Modified:           {modified_matches:6} ({modified_matches/stats.matched_function_count*100:.1f}%)")

    # Find most modified functions
    modified = sorted(
        [m for m in results.matches if m.similarity < 1.0],
        key=lambda m: m.similarity
    )

    if modified:
        print(f"\nMost Modified Functions (Top 10):")
        print("-" * 60)
        for i, match in enumerate(modified[:10], 1):
            print(f"{i:2}. {match.primary_name}")
            print(f"    Similarity: {match.similarity:5.1%}")
            print()


def analyze_algorithms(results):
    """Analyze which matching algorithms were used."""
    print("\nMatching Algorithm Analysis:")
    print("=" * 60)

    algorithm_stats = defaultdict(int)
    for match in results.matches:
        algorithm_stats[match.algorithm_id] += 1

    print(f"\nAlgorithm Distribution:")
    for algo_id, count in sorted(algorithm_stats.items(), key=lambda x: x[1], reverse=True):
        pct = (count / len(results.matches)) * 100
        print(f"  Algorithm {algo_id}: {count:6} ({pct:5.1f}%)")


def find_renamed_functions(results, min_similarity=0.95):
    """Find functions that were likely just renamed (high similarity, different names)."""
    print(f"\nLikely Renamed Functions (similarity >= {min_similarity:.0%}):")
    print("=" * 60)

    renamed = [
        m for m in results.matches
        if m.similarity >= min_similarity
        and m.primary_name != m.secondary_name
        and m.primary_name  # Skip empty names
        and m.secondary_name
    ]

    if renamed:
        for i, match in enumerate(renamed[:20], 1):
            print(f"{i:2}. {match.primary_name}")
            print(f"    -> {match.secondary_name}")
            print(f"    Similarity: {match.similarity:5.1%}")
            print()
    else:
        print("No renamed functions found.")


def export_csv(results, output_path):
    """Export results to CSV format."""
    import csv

    print(f"\nExporting to CSV: {output_path}")

    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Primary Address',
            'Primary Name',
            'Secondary Address',
            'Secondary Name',
            'Similarity',
            'Confidence',
            'Algorithm',
            'Manual',
        ])

        for match in results.matches:
            writer.writerow([
                f"0x{match.primary_address:x}",
                match.primary_name,
                f"0x{match.secondary_address:x}",
                match.secondary_name,
                f"{match.similarity:.4f}",
                f"{match.confidence:.4f}",
                match.algorithm_id,
                match.is_manual,
            ])

    print(f"Exported {len(results.matches)} matches to CSV")


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_results.py <results.db> [--export output.csv]")
        print()
        print("Example:")
        print("  analyze_results.py diff_results.db")
        print("  analyze_results.py diff_results.db --export results.csv")
        sys.exit(1)

    database = sys.argv[1]
    export_path = None

    if len(sys.argv) >= 4 and sys.argv[2] == '--export':
        export_path = sys.argv[3]

    if not Path(database).exists():
        print(f"Error: Database not found: {database}")
        sys.exit(1)

    print("BinDiff Results Analyzer")
    print("=" * 60)
    print(f"Database: {database}")
    print()

    # Load results
    print("Loading results...")
    results = bindiff.Results.load(database)

    # Basic summary
    results.print_summary()

    # Detailed analysis
    analyze_changes(results)
    analyze_algorithms(results)
    find_renamed_functions(results)

    # Export if requested
    if export_path:
        export_csv(results, export_path)

    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
