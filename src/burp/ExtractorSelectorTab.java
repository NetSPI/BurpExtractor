package burp;

import javax.swing.*;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.PrintWriter;
import java.io.IOException;

public class ExtractorSelectorTab implements ITab {

    private JTable requestTable;
    private JTable responseTable;
    private ExtractorMainTab mainTab;
    private IBurpExtenderCallbacks callbacks;
    private int messageCount = 0;

    public ExtractorSelectorTab(ExtractorMainTab mainTab, IBurpExtenderCallbacks callbacks) {
        this.mainTab = mainTab;
        this.callbacks = callbacks;
    }

    @Override
    public String getTabCaption() {
        return "Start";
    }

    private void addButtonPanel(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Add set of buttons at top of response table
        // Add paste button
        JPanel upperButtonPanel = new JPanel();
        upperButtonPanel.setLayout(new GridBagLayout());
        JButton pasteButton = new JButton("Paste");
        constraints.gridy = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        upperButtonPanel.add(pasteButton, constraints);
        pasteButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                addMessageFromClipboard();
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        // Add remove button
        JButton removeButton = new JButton("Remove");
        constraints.gridy = 1;
        upperButtonPanel.add(removeButton, constraints);
        removeButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int selected = responseTable.getSelectedRow();
                ((DefaultTableModel) responseTable.getModel()).removeRow(selected);
                ((DefaultTableModel) requestTable.getModel()).removeRow(selected);
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        // Add clear button
        JButton clearButton = new JButton("Clear");
        constraints.gridy = 2;
        upperButtonPanel.add(clearButton, constraints);
        clearButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                // Reset response table
                responseTable.setModel(getTableModel());
                responseTable.removeColumn(responseTable.getColumn("ByteData"));
                responseTable.removeColumn(responseTable.getColumn("Host"));

                // Reset request table
                requestTable.setModel(getTableModel());
                requestTable.removeColumn(requestTable.getColumn("ByteData"));
                requestTable.removeColumn(requestTable.getColumn("Host"));
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        constraints.gridx = 1;
        constraints.gridy = 1;
        constraints.weightx = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.NORTH;
        pane.add(upperButtonPanel, constraints);
    }

    private void addGoButton(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        JButton goButton = new JButton("Go");
        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.anchor = GridBagConstraints.SOUTH;
        JPanel goPanel = new JPanel();
        goPanel.add(goButton);
        pane.add(goPanel, constraints);
        goButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int selectedResponse = responseTable.getSelectedRow();
                byte[] response = (byte[]) responseTable.getModel().getValueAt(selectedResponse, 3);
                String responseHost = (String) responseTable.getModel().getValueAt(selectedResponse, 4);

                int selectedRequest = requestTable.getSelectedRow();
                byte[] request = (byte[]) requestTable.getModel().getValueAt(selectedRequest, 3);
                String requestHost = (String) requestTable.getModel().getValueAt(selectedRequest, 4);

                mainTab.createExtractorTab(response, request, responseHost, requestHost, callbacks);
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
    }

    private void addLabels(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Create request table label
        JLabel requestLabel = new JLabel("Select request to insert data into:");
        requestLabel.setBorder(BorderFactory.createEmptyBorder(4,0,4,0));
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        pane.add(requestLabel, constraints);

        // Create response table label
        JLabel responseLabel = new JLabel("Select response to extract data from:");
        responseLabel.setBorder(BorderFactory.createEmptyBorder(4,0,4,0));
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.weighty = 0;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        pane.add(responseLabel, constraints);
    }

    private void createTables(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Create request table
        DefaultTableModel requestModel = (DefaultTableModel) getTableModel();
        this.requestTable = new JTable(requestModel) {
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                c.setForeground(Color.black);
                return c;
            }
        };
        this.requestTable.setAutoCreateRowSorter(true);
        this.requestTable.removeColumn(this.requestTable.getColumn("ByteData"));
        this.requestTable.removeColumn(this.requestTable.getColumn("Host"));
        JScrollPane requestScrollPane = new JScrollPane(this.requestTable);
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.weighty = 0.5;
        constraints.weightx= 1;
        constraints.fill = GridBagConstraints.BOTH;
        constraints.anchor = GridBagConstraints.CENTER;
        pane.add(requestScrollPane, constraints);

        // Create response table
        DefaultTableModel responseModel = (DefaultTableModel) getTableModel();
        this.responseTable = new JTable(responseModel) {
            public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
                Component c = super.prepareRenderer(renderer, row, column);
                c.setForeground(Color.black);
                return c;
            }
        };
        this.responseTable.setAutoCreateRowSorter(true);
        this.responseTable.removeColumn(this.responseTable.getColumn("ByteData"));
        this.responseTable.removeColumn(this.responseTable.getColumn("Host"));
        JScrollPane responseScrollPane = new JScrollPane(this.responseTable);
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.weighty = 0.5;
        constraints.weightx= 1;
        constraints.fill = GridBagConstraints.BOTH;
        pane.add(responseScrollPane, constraints);
    }

    public TableModel getTableModel() {
        return new DefaultTableModel(new Object[] {"#", "Length", "Data", "ByteData", "Host"}, 0) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
    }

    @Override
    public Component getUiComponent() {

        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createMatteBorder(5,5,5, 5, new Color(255,255,255)));
        pane.setLayout(new GridBagLayout());
        GridBagConstraints constraints = new GridBagConstraints();

        addLabels(pane);
        addButtonPanel(pane);
        addGoButton(pane);
        createTables(pane);

        return pane;
    }

    public void addMessageFromClipboard() {
        String clipboardData;
        try {
            clipboardData = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
        } catch (IOException | UnsupportedFlavorException error) {
            PrintWriter errorWriter = new PrintWriter(callbacks.getStderr());
            errorWriter.println(error.getMessage());
            return;
        }

        DefaultTableModel model = (DefaultTableModel) this.requestTable.getModel();
        model.addRow(new Object[] {this.messageCount, clipboardData.length(), clipboardData, clipboardData.getBytes(), ""});

        model = (DefaultTableModel) this.responseTable.getModel();
        model.addRow(new Object[] {this.messageCount, clipboardData.length(), clipboardData, clipboardData.getBytes(), ""});

        this.messageCount++;
    }

    public void addMessageFromMenu(IHttpRequestResponse message) {
        DefaultTableModel model = (DefaultTableModel) this.requestTable.getModel();
        byte[] request = message.getRequest();
        String requestStr = new String(request);
        model.addRow(new Object[] {this.messageCount, requestStr.length(), requestStr, request, message.getHttpService().getHost()});

        model = (DefaultTableModel) this.responseTable.getModel();
        byte[] response = message.getResponse();
        String responseStr = new String(response);
        model.addRow(new Object[] {this.messageCount, responseStr.length(), responseStr, response, message.getHttpService().getHost()});

        this.messageCount++;
    }
}
