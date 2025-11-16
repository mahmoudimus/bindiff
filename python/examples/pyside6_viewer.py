#!/usr/bin/env python3
"""
BinDiff PySide6 Viewer

A basic GUI application for viewing BinDiff results using PySide6.

This demonstrates how to use the BinDiff Python interface with PySide6
instead of IDA's native forms.

Requirements:
    pip install PySide6
"""

import sys
from pathlib import Path

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QTableWidget, QTableWidgetItem, QFileDialog,
        QHeaderView, QGroupBox, QTextEdit, QSplitter, QProgressBar,
    )
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
except ImportError:
    print("Error: PySide6 not installed")
    print("Please install it with: pip install PySide6")
    sys.exit(1)

import bindiff


class BinDiffViewer(QMainWindow):
    """Main window for BinDiff results viewer."""

    def __init__(self):
        super().__init__()
        self.results = None
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("BinDiff Viewer")
        self.setGeometry(100, 100, 1200, 800)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Top toolbar
        toolbar = QHBoxLayout()
        self.load_btn = QPushButton("Load Database")
        self.load_btn.clicked.connect(self.load_database)
        toolbar.addWidget(self.load_btn)

        self.export_btn = QPushButton("Export CSV")
        self.export_btn.clicked.connect(self.export_csv)
        self.export_btn.setEnabled(False)
        toolbar.addWidget(self.export_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Statistics panel
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        self.stats_label = QLabel("No database loaded")
        self.stats_label.setFont(QFont("Monospace", 10))
        stats_layout.addWidget(self.stats_label)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

        # Splitter for table and details
        splitter = QSplitter(Qt.Vertical)

        # Matches table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Primary Name", "Secondary Name",
            "Similarity", "Confidence", "Algorithm", "Manual"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        splitter.addWidget(self.table)

        # Details panel
        details_group = QGroupBox("Match Details")
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Monospace", 9))
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        splitter.addWidget(details_group)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

        # Status bar
        self.statusBar().showMessage("Ready")

    def load_database(self):
        """Load a BinDiff database."""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Load BinDiff Database",
            "",
            "BinDiff Database (*.db *.BinDiff);;All Files (*)"
        )

        if not filename:
            return

        try:
            self.statusBar().showMessage(f"Loading {filename}...")
            QApplication.processEvents()

            # Load results
            self.results = bindiff.Results.load(filename)

            # Update UI
            self.update_statistics()
            self.update_table()

            self.export_btn.setEnabled(True)
            self.statusBar().showMessage(f"Loaded {filename}")

        except Exception as e:
            self.statusBar().showMessage(f"Error loading database: {e}")

    def update_statistics(self):
        """Update statistics display."""
        if not self.results:
            return

        stats = self.results.statistics

        text = f"""Functions:
  Primary:   {stats.primary_function_count:6}
  Secondary: {stats.secondary_function_count:6}
  Matched:   {stats.matched_function_count:6} ({stats.function_similarity:5.1%})

Basic Blocks:
  Primary:   {stats.primary_basic_block_count:6}
  Secondary: {stats.secondary_basic_block_count:6}
  Matched:   {stats.matched_basic_block_count:6} ({stats.basic_block_similarity:5.1%})

Instructions:
  Primary:   {stats.primary_instruction_count:6}
  Secondary: {stats.secondary_instruction_count:6}
  Matched:   {stats.matched_instruction_count:6} ({stats.instruction_similarity:5.1%})"""

        self.stats_label.setText(text)

    def update_table(self):
        """Update matches table."""
        if not self.results:
            return

        matches = self.results.matches
        self.table.setRowCount(len(matches))

        for i, match in enumerate(matches):
            self.table.setItem(i, 0, QTableWidgetItem(match.primary_name))
            self.table.setItem(i, 1, QTableWidgetItem(match.secondary_name))
            self.table.setItem(i, 2, QTableWidgetItem(f"{match.similarity:.2%}"))
            self.table.setItem(i, 3, QTableWidgetItem(f"{match.confidence:.2%}"))
            self.table.setItem(i, 4, QTableWidgetItem(str(match.algorithm_id)))
            self.table.setItem(i, 5, QTableWidgetItem("Yes" if match.is_manual else "No"))

        self.statusBar().showMessage(f"Displaying {len(matches)} matches")

    def on_selection_changed(self):
        """Handle table selection changes."""
        if not self.results:
            return

        selected = self.table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        match = self.results.matches[row]

        details = f"""Primary Function:
  Address:  0x{match.primary_address:x}
  Name:     {match.primary_name}

Secondary Function:
  Address:  0x{match.secondary_address:x}
  Name:     {match.secondary_name}

Match Information:
  Similarity:  {match.similarity:.4f} ({match.similarity:.2%})
  Confidence:  {match.confidence:.4f} ({match.confidence:.2%})
  Algorithm:   {match.algorithm_id}
  Manual:      {'Yes' if match.is_manual else 'No'}
  Flags:       0x{match.flags:x}"""

        self.details_text.setText(details)

    def export_csv(self):
        """Export results to CSV."""
        if not self.results:
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export to CSV",
            "bindiff_results.csv",
            "CSV Files (*.csv);;All Files (*)"
        )

        if not filename:
            return

        try:
            import csv

            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Primary Address', 'Primary Name',
                    'Secondary Address', 'Secondary Name',
                    'Similarity', 'Confidence', 'Algorithm', 'Manual'
                ])

                for match in self.results.matches:
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

            self.statusBar().showMessage(f"Exported to {filename}")

        except Exception as e:
            self.statusBar().showMessage(f"Error exporting: {e}")


def main():
    app = QApplication(sys.argv)
    viewer = BinDiffViewer()
    viewer.show()

    # Load database from command line if provided
    if len(sys.argv) > 1 and Path(sys.argv[1]).exists():
        # Defer loading until event loop starts
        from PySide6.QtCore import QTimer
        QTimer.singleShot(100, lambda: viewer.load_database_path(sys.argv[1]))

    sys.exit(app.exec())


# Helper method to load from path (for command line usage)
def load_database_path(self, path):
    try:
        self.results = bindiff.Results.load(path)
        self.update_statistics()
        self.update_table()
        self.export_btn.setEnabled(True)
        self.statusBar().showMessage(f"Loaded {path}")
    except Exception as e:
        self.statusBar().showMessage(f"Error loading database: {e}")

BinDiffViewer.load_database_path = load_database_path


if __name__ == "__main__":
    main()
