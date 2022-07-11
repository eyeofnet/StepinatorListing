// Modeled after ghidra/app/plugin/core/debug/gui/listing/DebuggerListingProvider.java

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

package com.eyeofnet.ghidra.stepinator;

import java.awt.BorderLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import ghidra.util.Swing;

import ghidra.program.util.ProgramLocation;
import ghidra.app.services.ProgramManager;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.model.DomainFile;

import docking.widgets.EventTrigger;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.util.Msg;
import resources.Icons;

public class StepinatorListingProvider extends CodeViewerProvider {

		public StepinatorListingProvider(StepinatorListingPlugin plugin, FormatManager formatManager,
                boolean isConnected) {
			super(plugin,formatManager,isConnected);
			mPlugin = plugin;
			//setVisible(true);
			createActions();
		}

		// TODO: Customize actions
		private void createActions() {
			//mAction = new DockingAction("Open Program", getName()) {
			//	@Override
			//	public void actionPerformed(ActionContext context) {
			//		context.
			//		activatedOpenProgram((StepinatorOpenProgramActionContext) context);
			//	}
			//};
			//mAction.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			//mAction.setEnabled(true);
			//mAction.markHelpUnnecessary();
			//dockingTool.addLocalAction(this, mAction);
		}

        @Override
        public void programLocationChanged(ProgramLocation location, EventTrigger trigger) {
                //locationLabel.goToAddress(location.getAddress());
                //if (traceManager != null) {
                //        location = ProgramLocationUtils.fixLocation(location, false);
                //}
                super.programLocationChanged(location, trigger);
                if (trigger == EventTrigger.GUI_ACTION) {
                        doSyncToStatic(location);
                        
                        doCheckCurrentModuleMissing();
                }
        }
        
        public void programOpened(Program program) {
            DomainFile df = program.getDomainFile();
            StepinatorOpenProgramActionContext ctx = new StepinatorOpenProgramActionContext(df);
        }

        public void programClosed(Program program) {
            if (program == mMarkedProgram) {
                    mMarkedProgram = null;
                    mMarkedAddress = null;
            }
        }

        @Override
        public boolean isConnected() {
                /*
                 * NB. Other plugins ask isConnected meaning the main static listing. We don't want to be
                 * mistaken for it.
                 */
                return false;
        }
        
        protected void doSyncToStatic(ProgramLocation location) {
            if (location != null) {
                    //ProgramLocation staticLoc = mappingService.getStaticLocationFromDynamic(location);
                    //if (staticLoc != null) {
                            Swing.runIfSwingOrRunLater(() -> mPlugin.fireStaticLocationEvent(location));
                    //}
            }
        }

        private void activatedOpenProgram(StepinatorOpenProgramActionContext context) {
            mProgramManager.openProgram(context.getDomainFile(), DomainFile.DEFAULT_VERSION,
                    ProgramManager.OPEN_CURRENT);
        }

        protected void doCheckCurrentModuleMissing() {
            /*
            ProgramLocation loc = getLocation();
            if (loc == null) {
                    return;
            }

            Address address = loc.getAddress();
            DomainFile df = ProgramURLUtils.getFileForHackedUpGhidraURL(tool.getProject(),
                            mapping.getStaticProgramURL());
                    if (df != null) {
                            doTryOpenProgram(df, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_CURRENT);
                    }
            }

            Set<TraceModule> missing = new HashSet<>();
            Set<DomainFile> toOpen = new HashSet<>();
            TraceModuleManager modMan = trace.getModuleManager();
            Collection<TraceModule> modules = Stream.concat(
                    modMan.getModulesAt(snap, address).stream().filter(m -> m.getSections().isEmpty()),
                    modMan.getSectionsAt(snap, address).stream().map(s -> s.getModule()))
                            .collect(Collectors.toSet());

            // Attempt to open probable matches. All others, attempt to import
            // TODO: What if sections are not presented?
            for (TraceModule mod : modules) {
                    Set<DomainFile> matches = mappingService.findProbableModulePrograms(mod);
                    if (matches.isEmpty()) {
                            missing.add(mod);
                    }
                    else {
                            toOpen.addAll(matches);
                    }
            }
            if (programManager != null && !toOpen.isEmpty()) {
                    for (DomainFile df : toOpen) {
                            // Do not presume a goTo is about to happen. There are no mappings, yet.
                            doTryOpenProgram(df, DomainFile.DEFAULT_VERSION,
                                    ProgramManager.OPEN_VISIBLE);
                    }
            }

            if (importerService == null || consoleService == null) {
                    return;
            }

            for (TraceModule mod : missing) {
                    consoleService.log(DebuggerResources.ICON_LOG_ERROR,
                            "<html>The module <b><tt>" + HTMLUtilities.escapeHTML(mod.getName()) +
                                    "</tt></b> was not found in the project</html>",
                            new DebuggerMissingModuleActionContext(mod));
            }
            */
        	
            /**
             * Once the programs are opened, including those which are successfully imported, the
             * section mapper should take over, eventually invoking callbacks to our mapping change
             * listener.
             */
        }

        protected Program mMarkedProgram;
        protected Address mMarkedAddress;        
        protected DockingAction mActionOpenProgram;
        
        private ProgramManager mProgramManager;
        private StepinatorListingPlugin mPlugin;
		private JPanel mPanel;
		private DockingAction mAction;


        private static final String TAG = "StepinatorListingProvider";
}
