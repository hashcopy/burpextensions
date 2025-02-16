# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JPanel, JButton, JTable, JScrollPane, JTextField, JLabel, JCheckBox, BoxLayout, JPopupMenu, JMenuItem, JOptionPane
from javax.swing.table import DefaultTableModel, TableRowSorter
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
import csv
import os

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("UniqueEndpoints")

        # UI Panel
        self.panel = JPanel(BorderLayout())

        # Create Filter Panel (Top)
        filter_panel = JPanel(GridLayout(2, 6))  # 2 rows, 6 columns (Filters + Extensions)

        self.filters = []
        column_names = ["S. No", "Endpoint", "Status", "Request", "Response"]
        for name in column_names:
            panel = JPanel(BorderLayout())
            panel.add(JLabel(name), BorderLayout.NORTH)
            field = JTextField(10)
            field.addActionListener(self.filter_data)
            panel.add(field, BorderLayout.CENTER)
            self.filters.append(field)
            filter_panel.add(panel)

        self.panel.add(filter_panel, BorderLayout.NORTH)

        # Create Extension Filter Panel
        extension_panel = JPanel(GridLayout(1, 6))
        extension_panel.add(JLabel("Exclude Extensions:"))

        self.extension_filters = {
            ".css": JCheckBox(".css", actionPerformed=self.filter_data),
            ".js": JCheckBox(".js", actionPerformed=self.filter_data),
            ".png": JCheckBox(".png", actionPerformed=self.filter_data),
            ".jpg": JCheckBox(".jpg", actionPerformed=self.filter_data),
            ".gif": JCheckBox(".gif", actionPerformed=self.filter_data),
            ".svg": JCheckBox(".svg", actionPerformed=self.filter_data),
        }

        for checkbox in self.extension_filters.values():
            extension_panel.add(checkbox)

        self.panel.add(extension_panel, BorderLayout.SOUTH)

        # Fetch Button
        self.fetch_button = JButton("Fetch Data", actionPerformed=self.fetch_endpoints)
        self.panel.add(self.fetch_button, BorderLayout.WEST)

        # Table Setup with Sorting
        self.column_names = column_names
        self.table_model = DefaultTableModel(self.column_names, 0)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)  # Enable sorting

        # Table Row Sorter for Dynamic Sorting
        self.table.setRowSorter(TableRowSorter(self.table_model))

        # Enable Copy-Paste Context Menu
        self.table.setComponentPopupMenu(self.create_popup_menu())

        scroll_pane = JScrollPane(self.table)
        self.panel.add(scroll_pane, BorderLayout.CENTER)

        # Save Button
        self.save_button = JButton("Save as CSV", actionPerformed=self.save_to_csv)
        self.panel.add(self.save_button, BorderLayout.EAST)

        callbacks.addSuiteTab(self)

        self.original_data = []

    def getTabCaption(self):
        return "Unique Endpoints"

    def getUiComponent(self):
        return self.panel

    def fetch_endpoints(self, event):
        """Fetches endpoints and populates the table"""
        unique_entries = []
        seen_entries = set()

        all_http_traffic = self.callbacks.getProxyHistory()

        if not all_http_traffic:
            return

        for item in all_http_traffic:
            if item is None or not isinstance(item, IHttpRequestResponse) or item.getRequest() is None:
                continue

            request_info = self.helpers.analyzeRequest(item.getRequest())

            headers = request_info.getHeaders()
            if not headers:
                continue

            host = "Unknown Host"
            path = "/"

            for header in headers:
                if header.lower().startswith("host:"):
                    host = header.split(": ", 1)[1]
                    break

            first_line = headers[0]  # Example: "GET /api/test HTTP/1.1"
            parts = first_line.split(" ")
            if len(parts) > 1:
                path = parts[1]  # Extract "/path"

            url_str = "https://" + host + path  # Assuming HTTP, change to HTTPS if needed

            # Extract Response Status Code
            response = item.getResponse()
            status_code = "No Response"
            if response:
                response_info = self.helpers.analyzeResponse(response)
                status_code = str(response_info.getStatusCode())

            unique_key = (url_str, status_code)

            if unique_key not in seen_entries:
                request = self.helpers.bytesToString(item.getRequest())
                response_text = self.helpers.bytesToString(response) if response else "No Response"

                unique_entries.append((len(unique_entries) + 1, url_str, status_code, request, response_text))
                seen_entries.add(unique_key)

        self.original_data = unique_entries
        self.filter_data(None)

    def filter_data(self, event):
        """Filters data based on user input and selected extensions"""
        filtered_rows = []

        # Get active exclusions
        excluded_extensions = [ext for ext, checkbox in self.extension_filters.items() if checkbox.isSelected()]

        for row in self.original_data:
            match = True

            # Apply column filters
            for i, field in enumerate(self.filters):
                filter_text = field.getText().strip().lower()
                if filter_text and filter_text not in str(row[i]).lower():
                    match = False
                    break

            # Apply extension exclusion
            if any(row[1].lower().endswith(ext) for ext in excluded_extensions):
                match = False

            if match:
                filtered_rows.append(row)

        self.update_table(filtered_rows)

    def update_table(self, data):
        self.table_model.setRowCount(0)
        for row in data:
            self.table_model.addRow(row)
        self.table.repaint()

    def save_to_csv(self, event):
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save CSV File")

        choice = file_chooser.showSaveDialog(self.panel)

        if choice == JFileChooser.APPROVE_OPTION:
            file = file_chooser.getSelectedFile()
            if file is None:
                return

            file_path = file.getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path += ".csv"

            try:
                with open(file_path, 'w', encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(self.column_names)

                    for row in range(self.table_model.getRowCount()):
                        writer.writerow([self.table_model.getValueAt(row, col) for col in range(len(self.column_names))])

                JOptionPane.showMessageDialog(self.panel, "Data saved to: " + file_path)

            except Exception as e:
                JOptionPane.showMessageDialog(self.panel, "Error saving file: " + str(e))

    def create_popup_menu(self):
        """Creates context menu for copying"""
        popup_menu = JPopupMenu()
        copy_item = JMenuItem("Copy", actionPerformed=self.copy_selected)
        popup_menu.add(copy_item)
        return popup_menu

    def copy_selected(self, event):
        """Copies selected table rows to clipboard"""
        selected_rows = self.table.getSelectedRows()
        if len(selected_rows) == 0:
            return

        copied_data = []
        MAX_CELL_LENGTH = 32000

        for row in selected_rows:
            row_data = []
            for col in range(self.table_model.getColumnCount()):
                cell_value = self.table_model.getValueAt(row, col)
                if cell_value is None:
                    cell_value = ""

                formatted_value = str(cell_value).replace("\r\n", "⏎ ").replace("\n", "⏎ ")

                if len(formatted_value) > MAX_CELL_LENGTH:
                    formatted_value = formatted_value[:MAX_CELL_LENGTH] + " [TRUNCATED]"

                row_data.append(formatted_value)

            copied_data.append("\t".join(row_data))

        clipboard_content = StringSelection("\n".join(copied_data))
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(clipboard_content, None)

        self.callbacks.issueAlert("Copied {} rows successfully!".format(len(selected_rows)))
