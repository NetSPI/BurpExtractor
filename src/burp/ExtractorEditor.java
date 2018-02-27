package burp;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;

public class ExtractorEditor {
    private IExtensionHelpers helpers;
    private JPanel pane;
    private ITextEditor textSelector;
    private JRadioButton useScope;
    private JRadioButton useCustomHost;
    private JTextField targetHost;
    private JCheckBox regexCheckBox;
    private JTextField regex;
    private boolean keyListenerSet;

    public ExtractorEditor(final IBurpExtenderCallbacks callbacks) {
        this.pane = new JPanel();
        this.helpers = callbacks.getHelpers();
        this.pane.setLayout(new GridBagLayout());

        // Add buttons to panel
        addButtons(this.pane);

        // Add text fields and labels to panel
        addTextFields(this.pane);

        // Add Burp response editor to panel
        addTextEditor(this.pane, callbacks);
    }

    // Add all buttons to editor
    private void addButtons(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Add radio button for scope
        this.useScope = new JRadioButton("Use suite scope");
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.gridwidth = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        this.pane.add(this.useScope, constraints);

        // Add radio button for target host
        this.useCustomHost = new JRadioButton("Use specified target host");
        constraints.gridx = 0;
        constraints.gridy = 1;
        constraints.gridwidth = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        this.pane.add(this.useCustomHost, constraints);

        // Create button group and select suite scope by default
        ButtonGroup scopeSelection = new ButtonGroup();
        scopeSelection.add(this.useScope);
        scopeSelection.add(this.useCustomHost);
        this.useScope.setSelected(true);
    }

    // Add our custom text editor
    private void addTextEditor(JPanel pane, IBurpExtenderCallbacks callbacks) {
        GridBagConstraints constraints = new GridBagConstraints();

        this.textSelector = callbacks.createTextEditor();
        this.textSelector.setEditable(true);
        JPanel panel = new JPanel(new GridBagLayout());
        constraints.gridx = 0;
        constraints.gridy = 0;
        constraints.weightx = 1;
        constraints.weighty = 1;
        constraints.fill = GridBagConstraints.BOTH;
        panel.add(this.textSelector.getComponent(), constraints);

        Border header = BorderFactory.createMatteBorder(4,0,0,0, Color.LIGHT_GRAY);
        panel.setBorder(header);

        constraints.gridx = 0;
        constraints.gridy = 4;
        constraints.gridwidth = 3;
        constraints.fill = GridBagConstraints.BOTH;
        constraints.weighty = 1;
        pane.add(panel, constraints);

        // This is used to select the focused component for an extractor editor.
        KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();

        // Create mouse listeners for message editor
        this.textSelector.getComponent().addMouseListener(new MouseListener() {


            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                // I never figured out how to get focus on the textEditor component to set keyListeners,
                // so just find out what is in focus when we click inside the editor and set a key listener on that.
                if (!keyListenerSet) {
                    keyListenerSet = true;
                    manager.getFocusOwner().addKeyListener(new KeyListener() {
                        @Override
                        public void keyTyped(KeyEvent e) {
                        }

                        @Override
                        public void keyPressed(KeyEvent e) {
                        }

                        @Override
                        public void keyReleased(KeyEvent e) {
                            regex.setText(buildSelectionRegex());
                        }
                    });
                }

                regex.setText(buildSelectionRegex());
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
    }

    // Add text fields and related labels
    private void addTextFields(JPanel pane) {
        GridBagConstraints constraints = new GridBagConstraints();

        // Add label for target host
        JLabel targetLabel = new JLabel("Target host: ");
        constraints.gridx = 0;
        constraints.gridy = 2;
        constraints.gridwidth = 1;
        constraints.fill = GridBagConstraints.NONE;
        constraints.weightx = 0;
        this.pane.add(targetLabel, constraints);

        // Add text field for target host
        this.targetHost = new JTextField();
        constraints.gridx = 1;
        constraints.gridy = 2;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        this.pane.add(this.targetHost, constraints);

        // Add regex checkBox
        this.regexCheckBox = new JCheckBox("Regex");
        constraints.gridx = 2;
        constraints.gridy = 2;
        constraints.fill = GridBagConstraints.NONE;
        constraints.weightx = 0;
        this.pane.add(this.regexCheckBox, constraints);

        // Add label for regex
        JLabel regexLabel = new JLabel("Regex: ");
        constraints.gridx = 0;
        constraints.gridy = 3;
        constraints.fill = GridBagConstraints.NONE;
        constraints.weightx = 0;
        this.pane.add(regexLabel, constraints);

        // Add text field for regex
        this.regex = new JTextField();
        constraints.gridx = 1;
        constraints.gridy = 3;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.weightx = 1;
        this.pane.add(this.regex, constraints);
    }

    // Build regex to represent the selected text in its appropriate context
    private String buildSelectionRegex() {

        // Only perform action if user has selected something
        if (textSelector.getSelectedText().length > 0) {
            int[] bounds = textSelector.getSelectionBounds();
            byte[] message = textSelector.getText();

            // Get start expression (13 characters or fewer if necessary)
            int[] startExpressionBounds = new int[2];
            if (bounds[0] < 13) {
                startExpressionBounds[0] = 0;
            } else {
                startExpressionBounds[0] = bounds[0] - 13;
            }
            startExpressionBounds[1] = bounds[0];
            byte[] startExpression = Arrays.copyOfRange(message, startExpressionBounds[0], startExpressionBounds[1]);

            // Get end delimeter (13 characters or fewer if necessary)
            int[] endDelimeterBounds = new int[2];
            int messageLength = message.length;
            endDelimeterBounds[0] = bounds[1];
            if (bounds[1] > messageLength - 13) {
                endDelimeterBounds[1] = messageLength;
            } else {
                endDelimeterBounds[1] = bounds[1] + 13;
            }
            byte[] endDelimeter = Arrays.copyOfRange(message, endDelimeterBounds[0], endDelimeterBounds[1]);

            // Build full regex
            String regex = "";
            String startText = this.helpers.bytesToString(startExpression);
            String endText = this.helpers.bytesToString(endDelimeter);

            // Build regex before string we want to select
            if (startText == "") {
                if (endText == "") {
                    return null;
                }
            } else if (startText.length() < 13){
                regex += "(^" + this.escapeRegex(startText) + ")";
            } else {
                regex += "(.*" + this.escapeRegex(startText) + ")";
            }

            regex += "(.*?)";

            // Build regex after string we want to select
            if (endText.length() < 13) {
                regex += "(" + endText + "$)";
            } else {
                regex += "("  + this.escapeRegex(endText) + ".*)";
            }

            return regex;
        } else {
            return null;
        }
    }

    // I hope that all necessary characters are escaped here, but I'm no regex pro so this could be faulty
    private String escapeRegex(String regex) {

        // Escape all regex chars
        regex = regex.replaceAll("([!$^&*()-+{\\[}\\]|\\\\:,.?])", "\\\\$1")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
        return regex;
    }

    public void fillTextArea(byte[] text) {
        this.textSelector.setText(text);
    }

    // Get regex string which represents the context of the selected text
    public String getSelectionRegex() {
        return this.regex.getText();
    }

    public String getTargetHost() {
        return this.targetHost.getText();
    }

    public void setTargetHost(String host) {
        this.targetHost.setText(host);
    }

    public boolean useRegexForTarget() {
        return this.regexCheckBox.isSelected();
    }

    public JPanel getUIComponent() {
        return this.pane;
    }

    // Returns true if suite scope should be used to determine if a message is in scope
    public boolean useSuiteScope() {
        return this.useScope.isSelected();
    }
}
