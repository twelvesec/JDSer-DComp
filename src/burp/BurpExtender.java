/*
 * Copyright (c) John Murray (2015), Twelvesec (2016)
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;


import javax.swing.*;

import twelvesec.TSUtils;

import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory {


	private static final String LIB_DIR = System.getProperty("user.dir") + "/libs/";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {    	
    	
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Twelvesec's JDSer-DComp Burp Extender, based on JDSer-ngng");

        JDTabFactory tab = new JDTabFactory(this.callbacks, this.helpers);

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(tab);

        // Enable "send to intruder" to contextual menu
        callbacks.registerContextMenuFactory(new JDMenu(this.callbacks, this.helpers));

        callbacks.registerHttpListener(new JDHttpListener(this.helpers));

        TSUtils.refreshSharedClassLoader();
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new JDTab(controller, editable, this.callbacks, this.helpers);
    }

    //
    // implement IContextMenuFactory
    //
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        Action reloadJarsAction = new ReloadJarsAction("JDSer-DComp: Reload JARs", invocation);
        JMenuItem reloadJars = new JMenuItem(reloadJarsAction);
        
        menu.add(reloadJars);
        return menu;
    }
    
    class ReloadJarsAction extends AbstractAction {

        IContextMenuInvocation invocation;
        
        public ReloadJarsAction(String text, IContextMenuInvocation invocation) {
            super(text);
            this.invocation = invocation;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
           System.out.println("Reloading jars from " + LIB_DIR);
           TSUtils.refreshSharedClassLoader();
        }
        
    }
}