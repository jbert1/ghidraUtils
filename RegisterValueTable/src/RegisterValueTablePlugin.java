/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package registervaluetable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JComponent;
import docking.ComponentProvider;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.Function;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Displays register values",
	description = "Displays the register values for a selected " +
					"address within the body of a function"
)
//@formatter:on

public class RegisterValueTablePlugin extends ProgramPlugin {

	RegisterTableComponentProvider provider;
	
	private RegisterTableModel model;
	private GhidraTable table;
	private JScrollPane component;
	private Address currentAddress = null;
	private Function currentFunction = null;
	private SymbolicPropogator symbolicPropogator;

	/**
	 * Plugin constructor.
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public RegisterValueTablePlugin(PluginTool tool) {
		super(tool, true, true);
	}

	@Override
	public void init() {
		super.init();
		model = new RegisterTableModel();
		table = new GhidraTable(model);
		component = new JScrollPane(table);
		provider = new RegisterTableComponentProvider(this);
	}

	/**
	 * Update the data within the table
	 */
	public void updateTable() {
		Function checkFn;
		// Update the current selected address
		currentAddress = currentLocation.getAddress();
		if (currentAddress == null) {
			return;
		}
		// See if we have a new function
		checkFn = currentProgram.getListing().getFunctionContaining(currentAddress);
		if (checkFn == null) {
			return;
		}
		if (currentFunction == null || 
				!currentFunction.getEntryPoint().equals(checkFn.getEntryPoint())) {
			// Update the function and symbolic propogator
			currentFunction = checkFn;
			updateSymbolicPropogator(currentFunction);
		}
		// Make very sure that our symbolic propogator is initialized
		if (symbolicPropogator == null) {
			updateSymbolicPropogator(currentFunction);
		}
		// Clear the current table and add the new Registers and values
		model.clear();
		for (Register register : currentProgram.getLanguage().getRegisters()) {
			SymbolicPropogator.Value val = symbolicPropogator.getRegisterValue(currentAddress, register);
			// Only add Registers to our table that actually have values
			if (val != null) {
				model.add(register, val.getValue());
			}
		}
		// Update the subtitle to the address we selected
		provider.setSubTitle(currentFunction.toString() + " (" + currentAddress.toString() + ")");
	}
	
	/**
	 * Update the symbolic propogator from a given function
	 *  (static-access suppress from the DUMMY monitor)
	 * @param Function to analyze
	 */
	@SuppressWarnings("static-access")
	public void updateSymbolicPropogator(Function function) {
		// Create a clean symbolic propogator
		symbolicPropogator = new SymbolicPropogator(currentProgram);
		try {
			// Attempt to update its analysis region with the given function
			symbolicPropogator.flowConstants(function.getEntryPoint(), function.getBody(),
					new ContextEvaluatorAdapter(), true, ConsoleTaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			return;
		}
	}
	
	/**
	 * Called when the user selects a new address
	 * @param current location in the program
	 */
	@Override
	public void locationChanged(ProgramLocation location) {
		super.locationChanged(location);
		if (location == null) {
			return;
		}
		updateTable();
	}
	
	/**
	 * Provides the interface between our table and Ghidra's GUI elements
	 */
	public class RegisterTableComponentProvider extends ComponentProvider {

		public RegisterTableComponentProvider(Plugin plugin) {
			super(plugin.getTool(), "Register Values", plugin.getName());
			buildGUI();
		}

		/**
		 * GUI Customizations
		 */
		private void buildGUI() {
			setIcon(ResourceManager.loadImage("images/memory16.gif"));
			setVisible(true);
		}
		
		/**
		 * Return our table when called
		 */
		@Override
		public JComponent getComponent() {
			return component;
		}
	}
	
	/**
	 * Sortable Table Model that houses Registers and corresponding values
	 */
	private static class RegisterTableModel extends AbstractSortedTableModel<RegisterValueObject> {

		final static int NAME_COL = 0;
		final static int LONG_VALUE_COL = 1;
		final static int HEX_VALUE_COL = 2;
		private List<RegisterValueObject> data = new ArrayList<>();
		
		/**
		 * Clear all elements in the table
		 */
		public void clear() {
			data = new ArrayList<>();
			fireTableDataChanged();
		}
		
		/**
		 * Add an element to our table
		 * @param register Register that houses a value
		 * @param value Long value for a corresponding register
		 */
		public void add(Register register, Long value) {
			if (register == null || value == null) {
				return;
			}
			RegisterValueObject regVal = new RegisterValueObject(register, value);
			if (contains(regVal)) {
				return;
			}
			data.add(regVal);
			// Update the table
			fireTableDataChanged();
		}
		
		/**
		 * Determines if a value is already within our data
		 * @param regVal Value to check within our data
		 * @return boolean whether the value already exists
		 */
		public boolean contains(RegisterValueObject regVal) {
			// Iterate over the data
			Iterator<RegisterValueObject> iter = data.iterator();
			while (iter.hasNext()) {
				RegisterValueObject checkRegVal = iter.next();
				// Only return true if there is an entry that has the same register name
				//  and register value
				if (checkRegVal.getRegister().getName().equals(regVal.getRegister().getName()) &&
						checkRegVal.getValue() == regVal.getValue()) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Only allow sorting by name
		 * @param columnIndex column number that is currently iterated\
		 * @return boolean value for whether or not the column is sortable 
		 */
		@Override
		public boolean isSortable(int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return true;
				default:
					return false;
			}
		}
		
		/**
		 * Column count will always be 3 
		 * @return int number of columns
		 */
		@Override
		public int getColumnCount() {
			return 3;
		}

		/**
		 * Name for the Object
		 * @return String name of the object
		 */
		@Override
		public String getName() {
			return "Register Values";
		}

		/**
		 * Return the List of table elements
		 * @return List of TableRegisterEntry items
		 */
		@Override
		public List<RegisterValueObject> getModelData() {
			return data;
		}

		/**
		 * Get the value in the table
		 * @param regVal TableRegisterEntry object that houses our registers and values
		 * @param columnIndex column number that is currently iterated
		 * @return String column value for the iterated row
		 */
		@Override
		public Object getColumnValueForRow(RegisterValueObject regVal, int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return regVal.getRegister().toString();
				case LONG_VALUE_COL:
					return regVal.getValue().toString();
				case HEX_VALUE_COL:
					return Long.toHexString(regVal.getValue());
				default:
					return null;
			}
		}
		
		/**
		 * Return the column name for a given column index
		 * @param columnIndex column number that is currently iterated
		 * @return String name for the column
		 */
		@Override
		public String getColumnName(int columnIndex) {
			switch (columnIndex) {
				case NAME_COL:
					return "Register Name";
				case LONG_VALUE_COL:
					return "Value (d)";
				case HEX_VALUE_COL:
					return "Value (h)";
				default:
					return null;
			}
		}	
	}	
}