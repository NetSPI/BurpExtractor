package burp;

import burp.persistence.InScopeTools;
import burp.persistence.Persistor;
import burp.persistence.RequestResponseState;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;

public class ExtractorEditor {
	private IExtensionHelpers helpers;
	private JPanel pane;
	private ITextEditor textSelector;
	private HashMap<Integer, ToolMenuItem> toolSelectors;
	private ToolMenuItem allTools;
	private JRadioButton useScope;
	private JRadioButton useCustomHost;
	private JTextField targetHost;
	private JCheckBox regexCheckBox;
	private JTextField beforeRegex;
	private JTextField afterRegex;
	private boolean keyListenerSet;
	private final int SELECTION_BUFFER = 15;
	private Logger logger;

	public ExtractorEditor(final IBurpExtenderCallbacks callbacks) {
		this.pane = new JPanel();
		this.helpers = callbacks.getHelpers();
		this.logger = new Logger(new PrintWriter(callbacks.getStdout(), true));
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
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

		// Create tool selection
		toolSelectors = new HashMap<Integer, ToolMenuItem>();
		JButton toolSelectionBar = new JButton("Select in-scope tools");
		JPopupMenu toolSelection = new JPopupMenu();
		this.allTools = new ToolMenuItem("All", true);
		toolSelection.add(this.allTools);
		ToolMenuItem proxyTool = new ToolMenuItem("Proxy", true);
		toolSelectors.put(IBurpExtenderCallbacks.TOOL_PROXY, proxyTool);
		toolSelection.add(proxyTool);
		ToolMenuItem scannerTool = new ToolMenuItem("Scanner", true);
		toolSelectors.put(IBurpExtenderCallbacks.TOOL_SCANNER, scannerTool);
		toolSelection.add(scannerTool);
		ToolMenuItem intruderTool = new ToolMenuItem("Intruder", true);
		toolSelectors.put(IBurpExtenderCallbacks.TOOL_INTRUDER, intruderTool);
		toolSelection.add(intruderTool);
		ToolMenuItem repeater = new ToolMenuItem("Repeater", true);
		toolSelectors.put(IBurpExtenderCallbacks.TOOL_REPEATER, repeater);
		toolSelection.add(repeater);
		toolSelectionBar.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				toolSelection.show(toolSelectionBar, 0, toolSelectionBar.getHeight());
			}
		});
		buttonPanel.add(toolSelectionBar);

		// Create button for testing regex
		JButton testRegexButton = new JButton("Test defined selection");
		testRegexButton.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				String matchResult = getTestRegexMatch();
				JPopupMenu popup = new JPopupMenu();
				JLabel contents = new JLabel();
				if (matchResult == null) {
					contents.setText("Did not find a match for the defined start and end regex!");
				} else {
					contents.setText("Found match: " + matchResult);
				}
				contents.setBorder(BorderFactory.createEmptyBorder(4,4,4,4));
				popup.add(contents);
				popup.show(testRegexButton, 0, testRegexButton.getHeight());
			}
		});
		buttonPanel.add(testRegexButton);

		GridBagConstraints constraints = new GridBagConstraints();
		constraints.gridx = 0;
		constraints.gridy = 0;
		constraints.gridwidth = 4;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		pane.add(buttonPanel, constraints);
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
		constraints.gridwidth = 4;
		constraints.fill = GridBagConstraints.BOTH;
		constraints.weighty = 1;
		pane.add(panel, constraints);

		// This is used to select the focused component for an extractor editor.
		KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();

		// Create mouse listeners for message editor
		this.textSelector.getComponent().addMouseListener(new MouseAdapter() {
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
							String [] selectionRegex = buildSelectionRegex();
							if (selectionRegex != null) {
								beforeRegex.setText(selectionRegex[0]);
								afterRegex.setText(selectionRegex[1]);
							}
						}
					});
				}
				String [] selectionRegex = buildSelectionRegex();
				if (selectionRegex != null) {
					beforeRegex.setText(selectionRegex[0]);
					afterRegex.setText(selectionRegex[1]);
				}
			}
		});
	}

	// Add text fields and related labels
	private void addTextFields(JPanel pane) {
		GridBagConstraints constraints = new GridBagConstraints();

		// Add label for target host
		JPanel targetPanel = new JPanel(new GridBagLayout());
		GridBagConstraints targetConstraints = new GridBagConstraints();

		// Add radio button for scope
		this.useScope = new JRadioButton("Use suite scope  ");
		this.useScope.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				Persistor.persistExtractor();
			}
		});
		targetConstraints.gridx = 0;
		targetPanel.add(this.useScope, targetConstraints);

		// Add radio button for target host
		this.useCustomHost = new JRadioButton("Use specified target host: ");
		targetConstraints.gridx += 1;
		targetPanel.add(this.useCustomHost, targetConstraints);

		// Create button group and select suite scope by default
		ButtonGroup scopeSelection = new ButtonGroup();
		scopeSelection.add(this.useScope);
		scopeSelection.add(this.useCustomHost);
		this.useScope.setSelected(true);

		// Add text field for target host
		this.targetHost = new JTextField();
		this.targetHost.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				Persistor.persistExtractor();

			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}
		});
		targetConstraints.gridx += 1;
		targetConstraints.weightx = 1;
		targetConstraints.fill = GridBagConstraints.HORIZONTAL;
		targetPanel.add(this.targetHost, targetConstraints);

		// Add regex checkBox
		this.regexCheckBox = new JCheckBox("Regex");
		this.regexCheckBox.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Persistor.persistExtractor();
			}
		});
		targetConstraints.gridx += 1;
		targetConstraints.weightx = 0;
		targetConstraints.fill = GridBagConstraints.NONE;
		targetPanel.add(this.regexCheckBox, targetConstraints);

		constraints.gridx = 0;
		constraints.gridwidth = 4;
		constraints.gridy = 1;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		this.pane.add(targetPanel, constraints);

		// Add label for beforeRegex
		JLabel regexLabel = new JLabel("Before Regex: ");
		constraints.gridx = 0;
		constraints.gridwidth = 1;
		constraints.gridy = 2;
		constraints.fill = GridBagConstraints.NONE;
		constraints.weightx = 0;
		this.pane.add(regexLabel, constraints);

		// Add text field for beforeRegex
		this.beforeRegex = new JTextField();
		this.beforeRegex.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}
		});
		constraints.gridx = 1;
		constraints.gridy = 2;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.weightx = 1;
		this.pane.add(this.beforeRegex, constraints);

		// Add label for afterRegex
		JLabel endRegexLabel = new JLabel("After Regex: ");
		constraints.gridx = 2;
		constraints.gridwidth = 1;
		constraints.gridy = 2;
		constraints.fill = GridBagConstraints.NONE;
		constraints.weightx = 0;
		this.pane.add(endRegexLabel, constraints);

		// Add text field for afterRegex
		this.afterRegex = new JTextField();
		this.afterRegex.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				Persistor.persistExtractor();
			}
		});

		constraints.gridx = 3;
		constraints.gridy = 2;
		constraints.fill = GridBagConstraints.HORIZONTAL;
		constraints.weightx = 1;
		this.pane.add(this.afterRegex, constraints);
	}

	// Build regex to represent the selected text in its appropriate context
	private String[] buildSelectionRegex() {

		// Only perform action if user has selected something
		byte[] selected = textSelector.getSelectedText();
		if (textSelector.getSelectedText() != null) {
			int[] bounds = textSelector.getSelectionBounds();
			byte[] message = textSelector.getText();

			// Get start expression (SELECTION_BUFFER characters or fewer if necessary)
			int[] startExpressionBounds = new int[2];
			if (bounds[0] < SELECTION_BUFFER) {
				startExpressionBounds[0] = 0;
			} else {
				startExpressionBounds[0] = bounds[0] - SELECTION_BUFFER;
			}
			startExpressionBounds[1] = bounds[0];
			byte[] startExpression = Arrays.copyOfRange(message, startExpressionBounds[0], startExpressionBounds[1]);

			// Get end delimeter (SELECTION_BUFFER characters or fewer if necessary)
			int[] endDelimeterBounds = new int[2];
			int messageLength = message.length;
			endDelimeterBounds[0] = bounds[1];
			if (bounds[1] > messageLength - SELECTION_BUFFER) {
				endDelimeterBounds[1] = messageLength;
			} else {
				endDelimeterBounds[1] = bounds[1] + SELECTION_BUFFER;
			}
			byte[] endDelimeter = Arrays.copyOfRange(message, endDelimeterBounds[0], endDelimeterBounds[1]);

			// Build full regex
			String[] regex = new String[2];
			String startText = this.helpers.bytesToString(startExpression);
			String endText = this.helpers.bytesToString(endDelimeter);

			// Build beforeRegex before string we want to select
			if (startText == "" && endText == "") {
				return null;
			}

			if (startText.length() < SELECTION_BUFFER) {
				regex[0] = "^" + this.escapeRegex(startText);
			} else {
				regex[0] = this.escapeRegex(startText);
			}

			if (endText.length() < SELECTION_BUFFER) {
				regex[1] = this.escapeRegex(endText) + "$";
			} else {
				regex[1] = this.escapeRegex(endText);
			}
			return regex;
		} else {
			return null;
		}
	}

	private String getTestRegexMatch() {
		String toMatch = helpers.bytesToString(textSelector.getText());
		int[] selectionBounds = Utils.getSelectionBounds(toMatch,
				beforeRegex.getText(),
				afterRegex.getText());
		logger.debug("Testing regex...");
		logger.debug("String to match: " + toMatch);
		logger.debug("Start regex: " + beforeRegex.getText());
		logger.debug("End regex: " + afterRegex.getText());
		if (selectionBounds == null) {
			return null;
		}
		return toMatch.substring(selectionBounds[0], selectionBounds[1]);
	}

	// I hope that all necessary characters are escaped here, but I'm no regex pro so this could be faulty
	private String escapeRegex(String regex) {

		// Escape all regex chars
		regex = regex.replaceAll("([!$^&*()-+{\\[}\\]|\\\\:,.?])", "\\\\$1")
				.replace("\n", "\\n")
				.replace("\r", "\\r");
		return regex;
	}

	public boolean isToolSelected(int toolFlag) {
		return toolSelectors.containsKey(toolFlag) && toolSelectors.get(toolFlag).isSelected();
	}

	public void fillTextArea(byte[] text) {
		this.textSelector.setText(text);
	}

	// Get regex string which represents the context of the selected text
	public String[] getSelectionRegex() {
		return new String[] {this.beforeRegex.getText(), this.afterRegex.getText()};
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

	public String getEditorContent() {
		return this.helpers.bytesToString(this.textSelector.getText());
	}

	public RequestResponseState getEditorState() {
		InScopeTools tools = new InScopeTools(this.allTools.isSelected(),
				this.isToolSelected(IBurpExtenderCallbacks.TOOL_PROXY),
				this.isToolSelected(IBurpExtenderCallbacks.TOOL_SCANNER),
				this.isToolSelected(IBurpExtenderCallbacks.TOOL_INTRUDER),
				this.isToolSelected(IBurpExtenderCallbacks.TOOL_REPEATER));
		String[] requestSelectionRegex = this.getSelectionRegex();
		RequestResponseState state = new RequestResponseState(tools,
				this.useSuiteScope(),
				this.getTargetHost(),
				this.useRegexForTarget(),
				requestSelectionRegex[0],
				requestSelectionRegex[1],
				this.getEditorContent());
		return state;
	}

	public void setEditorState(RequestResponseState state) {
		this.allTools.setSelected(state.inScopeTools.allTools);
		this.toolSelectors.get(IBurpExtenderCallbacks.TOOL_PROXY).setSelected(state.inScopeTools.proxy);
		this.toolSelectors.get(IBurpExtenderCallbacks.TOOL_SCANNER).setSelected(state.inScopeTools.scanner);
		this.toolSelectors.get(IBurpExtenderCallbacks.TOOL_INTRUDER).setSelected(state.inScopeTools.intruder);
		this.toolSelectors.get(IBurpExtenderCallbacks.TOOL_REPEATER).setSelected(state.inScopeTools.repeater);
		this.useScope.setSelected(state.useSuiteScope);
		this.useCustomHost.setSelected(!state.useSuiteScope);
		this.targetHost.setText(state.targetHost);
		this.regexCheckBox.setSelected(state.useRegex);
		this.beforeRegex.setText(state.beforeRegex);
		this.afterRegex.setText(state.afterRegex);
		this.textSelector.setText(state.content.getBytes());
	}


	// Create our own MenuItem so that we can prevent closing on every click
	public class ToolMenuItem extends JCheckBoxMenuItem {

		public ToolMenuItem(String text, boolean selected) {
			super(text, selected);
		}

		@Override
		public void doClick() {
			super.doClick();
			if (this == allTools) {
				// Change all other menu items to match this status
				boolean selected = this.isSelected();
				for (ToolMenuItem menuItem : toolSelectors.values()) {
					menuItem.setSelected(selected);
				}
			} else {
				if (allTools.isSelected()) {
					// If allTools is selected, then everything else should be selected. Deselect allTools
					allTools.setSelected(false);
				}
			}
			logger.info("Saving in-scope....");
			Persistor.persistExtractor();
		}

		@Override
		protected void processMouseEvent(MouseEvent event) {
			if (event.getID() == MouseEvent.MOUSE_RELEASED && contains(event.getPoint())) {
				doClick();
				setArmed(true);
			} else {
				super.processMouseEvent(event);
			}
		}
	}
}
