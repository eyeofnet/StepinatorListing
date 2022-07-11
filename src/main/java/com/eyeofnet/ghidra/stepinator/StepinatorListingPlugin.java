// Modeled after ghidra/app/plugin/core/debug/gui/listing/DebuggerListingPlugin.java

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

import javax.swing.*;

import ghidra.util.Swing;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

import ghidra.app.services.ConsoleService;
import ghidra.app.services.ProgramManager;
import ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.ViewManagerService;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.events.ProgramLocationPluginEvent;

import ghidra.framework.plugintool.annotation.AutoServiceConsumed;

import utilities.util.SuppressableCallback;
import utilities.util.SuppressableCallback.Suppression;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here.",
    eventsConsumed = {
        ProgramLocationPluginEvent.class, // For static listing sync
    },
    servicesRequired = {
        ProgramManager.class, // For static listing sync
    }
)
//@formatter:on
public class StepinatorListingPlugin extends AbstractCodeBrowserPlugin<StepinatorListingProvider> {

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public StepinatorListingPlugin(PluginTool tool) {
		super(tool);
		
		mPluginTool = tool;
		mProvider = createNewDisconnectedProvider();

		//String topicName = this.getClass().getPackage().getName();
		//String anchorName = "HelpAnchor";
		//mProvider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}


	@Override
	public void locationChanged(CodeViewerProvider codeViewerProvider, ProgramLocation loc) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void highlightChanged(CodeViewerProvider codeViewerProvider, ProgramSelection highlight) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public ViewManagerService getViewManager(CodeViewerProvider codeViewerProvider) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public StepinatorListingProvider createNewDisconnectedProvider() {
		// TODO Auto-generated method stub
		return null;
	}

    public void addConsoleMessage(String tag, String msg) {
        if (null != mPluginTool) {
            ConsoleService cs = mPluginTool.getService(ConsoleService.class);
            if (null != cs) {
                    cs.addMessage(tag, msg);
            }
        }
    }
	
    @Override
    public Object getTransientState() {
            // ProgramManager?
            return new Object[] {};
    }
    
    void fireStaticLocationEvent(ProgramLocation staticLoc) {
        assert Swing.isSwingThread();
        try (Suppression supp = cbProgramLocationEvents.suppress(null)) {
                mProgramManager.setCurrentProgram(staticLoc.getProgram());
                tool.firePluginEvent(new ProgramLocationPluginEvent(getName(), staticLoc,
                        staticLoc.getProgram()));
        }
    }

	@Override
	protected StepinatorListingProvider createProvider(FormatManager formatManager, boolean isConnected) {
		return new StepinatorListingProvider(this, formatManager, isConnected);
	}
	
	StepinatorListingProvider mProvider;
    PluginTool mPluginTool;
    
    @AutoServiceConsumed
    private ProgramManager mProgramManager;

    private final SuppressableCallback<Void> cbProgramLocationEvents = new SuppressableCallback<>();

    private static final String TAG = "StepinatorListingPlugin";

}
