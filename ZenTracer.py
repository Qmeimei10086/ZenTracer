# -*- coding: utf-8 -*-
import base64
import json
import sys
import threading
import time
from copy import copy

import frida

from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QGridLayout, QTreeView, 
                            QListView, QMenuBar, QMenu, QStatusBar, QAction, QMessageBox, 
                            QFileDialog, QDialog, QLineEdit, QPushButton, QSizePolicy, 
                            QAbstractItemView, QHeaderView)
from PyQt5 import QtCore

APP = None  # type: ZenTracer

scripts = []
device = None


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1200, 800)
        MainWindow.setMaximumSize(QtCore.QSize(16777214, 16777215))
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        
        self.treeView = QTreeView(self.centralwidget)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.treeView.sizePolicy().hasHeightForWidth())
        self.treeView.setSizePolicy(sizePolicy)
        self.treeView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.treeView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.treeView.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.treeView.setExpandsOnDoubleClick(False)
        self.treeView.setObjectName("treeView")
        self.treeView.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.treeView.setAlternatingRowColors(True)
        self.gridLayout.addWidget(self.treeView, 0, 0, 1, 1)
        
        self.logList = QListView(self.centralwidget)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.logList.sizePolicy().hasHeightForWidth())
        self.logList.setSizePolicy(sizePolicy)
        self.logList.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.logList.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.logList.setObjectName("logList")
        self.logList.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.gridLayout.addWidget(self.logList, 1, 0, 1, 1)
        
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1200, 23))
        self.menubar.setObjectName("menubar")
        self.menuMenu = QMenu(self.menubar)
        self.menuMenu.setObjectName("menuMenu")
        self.menuAction = QMenu(self.menubar)
        self.menuAction.setObjectName("menuAction")
        self.menuHelp = QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        
        self.actionImport_jadx_jobf = QAction(MainWindow)
        self.actionImport_jadx_jobf.setObjectName("actionImport_jadx_jobf")
        self.actionExportJSON = QAction(MainWindow)
        self.actionExportJSON.setObjectName("actionExportJSON")
        self.actionImportJSON = QAction(MainWindow)
        self.actionImportJSON.setObjectName("actionImportJSON")
        self.actionStart = QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        self.actionAbout = QAction(MainWindow)
        self.actionAbout.setObjectName("actionAbout")
        self.actionBlack_Regex = QAction(MainWindow)
        self.actionBlack_Regex.setObjectName("actionBlack_Regex")
        self.actionMatch_Regex = QAction(MainWindow)
        self.actionMatch_Regex.setObjectName("actionMatch_Regex")
        self.actionClean = QAction(MainWindow)
        self.actionClean.setObjectName("actionClean")
        
        self.menuMenu.addAction(self.actionExportJSON)
        self.menuMenu.addAction(self.actionImportJSON)
        self.menuMenu.addSeparator()
        self.menuMenu.addAction(self.actionImport_jadx_jobf)
        self.menuAction.addAction(self.actionStart)
        self.menuAction.addAction(self.actionClean)
        self.menuAction.addSeparator()
        self.menuAction.addAction(self.actionMatch_Regex)
        self.menuAction.addAction(self.actionBlack_Regex)
        self.menuHelp.addAction(self.actionAbout)
        self.menubar.addAction(self.menuMenu.menuAction())
        self.menubar.addAction(self.menuAction.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        self.actionImport_jadx_jobf.triggered.connect(MainWindow.import_jobf_onClick)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "ZenTracer - Enhanced"))
        self.menuMenu.setTitle(_translate("MainWindow", "File"))
        self.menuAction.setTitle(_translate("MainWindow", "Action"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.actionImport_jadx_jobf.setText(_translate("MainWindow", "Import jadx-jobf"))
        self.actionExportJSON.setText(_translate("MainWindow", "Export JSON"))
        self.actionImportJSON.setText(_translate("MainWindow", "Import JSON"))
        self.actionStart.setText(_translate("MainWindow", "Start"))
        self.actionAbout.setText(_translate("MainWindow", "About"))
        self.actionBlack_Regex.setText(_translate("MainWindow", "Black RegEx"))
        self.actionMatch_Regex.setText(_translate("MainWindow", "Match RegEx"))
        self.actionClean.setText(_translate("MainWindow", "Clean"))


class ListDialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(390, 267)
        self.gridLayout = QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.listView = QListView(Dialog)
        self.listView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.listView.setAlternatingRowColors(False)
        self.listView.setObjectName("listView")
        self.gridLayout.addWidget(self.listView, 0, 0, 1, 3)
        self.lineEdit = QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 1, 0, 1, 1)
        self.add = QPushButton(Dialog)
        self.add.setObjectName("add")
        self.gridLayout.addWidget(self.add, 1, 1, 1, 1)
        self.remove = QPushButton(Dialog)
        self.remove.setObjectName("remove")
        self.gridLayout.addWidget(self.remove, 1, 2, 1, 1)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.add.setText(_translate("Dialog", "add"))
        self.remove.setText(_translate("Dialog", "remove"))


def FridaReceive(message, data):
    """处理Frida消息，同时输出到终端和GUI"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    
    if message['type'] == 'send':
        if 'payload' in message and message['payload'][:12] == 'ZenTracer:::':
            packet = json.loads(message['payload'][12:])
            cmd = packet['cmd']
            data = packet['data']
            if cmd == 'log':
                terminal_msg = f"[{timestamp}] [LOG] {data}"
                print(terminal_msg)
                APP.log(data)
            elif cmd == 'enter':
                tid, tName, cls, method, args, call_stack = data
                terminal_msg = f"[{timestamp}] [ENTER] {cls}.{method}({args}) [Thread: {tid}-{tName}]"
                print(terminal_msg)
                if call_stack:
                    terminal_msg += f"\nCall Stack:\n{call_stack}"
                APP.method_entry(tid, tName, cls, method, args)
            elif cmd == 'exit':
                tid, retval = data
                terminal_msg = f"[{timestamp}] [EXIT] Return: {retval} [Thread: {tid}]"
                print(terminal_msg)
                APP.method_exit(tid, retval)
            elif cmd == 'detailed_log':
                terminal_msg = f"[{timestamp}] [DETAIL] {data}"
                print(terminal_msg)
        else:
            terminal_msg = f"[{timestamp}] [SEND] {message.get('payload', '')}"
            print(terminal_msg)
    elif message['type'] == 'error':
        terminal_msg = f"[{timestamp}] [ERROR] {message.get('stack', message.get('description', ''))}"
        print(terminal_msg)
    else:
        terminal_msg = f"[{timestamp}] [{message['type'].upper()}] {message}"
        print(terminal_msg)


class TraceItem:
    def __init__(self, clazz, method, args, parent_item=None, retval=None):
        self.clazz = clazz
        self.method = method
        self.args = args
        self.retval = retval
        self.parent_item = parent_item
        self.child_items = []
        
        # 创建三个列的项目
        self.method_item = QStandardItem(self._format_method_text())
        self.args_item = QStandardItem(self._format_text(args))
        self.retval_item = QStandardItem(self._format_text(retval))
        
        # 设置项目为不可编辑
        self.method_item.setEditable(False)
        self.args_item.setEditable(False)
        self.retval_item.setEditable(False)
        
        # 如果提供了父项目，将当前项目添加到父项目中
        if parent_item:
            parent_item.appendRow([self.method_item, self.args_item, self.retval_item])
            if hasattr(parent_item, 'child_items'):
                parent_item.child_items.append(self)

    def _format_method_text(self):
        return f"{self.clazz}.{self.method}"

    def _format_text(self, text):
        """格式化文本，确保显示对齐"""
        if text is None:
            return ""
        if isinstance(text, str):
            # 如果文本太长，进行截断
            if len(text) > 100:
                return text[:97] + "..."
            return text
        return str(text)

    def set_args(self, args):
        self.args = args
        self.args_item.setText(self._format_text(args))

    def set_retval(self, retval):
        self.retval = retval
        self.retval_item.setText(self._format_text(retval))

    def add_child(self, child_item):
        """添加子项目"""
        self.child_items.append(child_item)

    def get_method_item(self):
        """返回方法列的项目，用于TreeView显示"""
        return self.method_item


class ListWindow(QDialog):
    data = None  # type: list[str]

    def __init__(self, data, title):
        super().__init__(APP.window)
        self.data = data
        self.ui = ListDialog()
        self.ui.setupUi(self)
        self.setWindowTitle(title)
        self.setupList()
        self.setupAction()

    def setupList(self):
        model = QStandardItemModel(self.ui.listView)
        self.ui.listView.setModel(model)
        unique_data = []
        for item in self.data:
            if item not in unique_data:
                unique_data.append(item)
        self.data.clear()
        self.data.extend(unique_data)
        
        for item in self.data:
            list_item = QStandardItem(item)
            list_item.setEditable(False)
            model.appendRow(list_item)

    def setupAction(self):
        self.ui.add.clicked.connect(self.add)
        self.ui.remove.clicked.connect(self.remove)

    def add(self):
        text = self.ui.lineEdit.text().strip()
        if text:
            if text in self.data:
                print('[*] INFO: {} is already exists'.format(text))
                return
            self.data.append(text)
            item = QStandardItem(text)
            item.setEditable(False)
            self.ui.listView.model().appendRow(item)
            self.ui.lineEdit.clear()

    def remove(self):
        selected = self.ui.listView.selectedIndexes()
        if selected:
            index = selected[0].row()
            if 0 <= index < len(self.data):
                del self.data[index]
                self.ui.listView.model().removeRow(index)


def start_trace(app):
    global scripts
    global device

    def _attach(pid):
        if not device: 
            return
        try:
            app.log("Attaching to process: {}".format(pid))
            print(f"[*] Attaching to process: {pid}")
            
            session = device.attach(pid)
            if hasattr(session, 'enable_child_gating'):
                session.enable_child_gating()
            
            try:
                with open('trace_enhanced.js', 'r', encoding='utf-8') as f:
                    source = f.read()
            except Exception as e:
                try:
                    with open('trace.js', 'r', encoding='utf-8') as f:
                        source = f.read()
                except Exception as e2:
                    error_msg = f"Error: Cannot read trace.js file: {str(e2)}"
                    app.log(error_msg)
                    print(error_msg)
                    return
            
            source = source.replace('{MATCHREGEX}', json.dumps(app.match_regex_list))\
                          .replace("{BLACKREGEX}", json.dumps(app.black_regex_list))
            
            script = session.create_script(source)
            script.on("message", FridaReceive)
            script.load()
            scripts.append(script)
            
            success_msg = f"Script loaded successfully for PID: {pid}"
            app.log(success_msg)
            print(success_msg)
            
        except Exception as e:
            error_msg = f"Error attaching to {pid}: {str(e)}"
            app.log(error_msg)
            print(error_msg)

    def _on_child_added(child):
        print(f"[*] Child process added: {child.pid}")
        _attach(child.pid)

    try:
        print("[*] Getting USB device...")
        device = frida.get_usb_device()
        print(f"[*] Device: {device.name}")
        
        device.on("child-added", _on_child_added)
        
        target_app = None
        try:
            application = device.get_frontmost_application()
            if application:
                target_app = application
                print(f"[*] Frontmost application: {application.identifier} (PID: {application.pid})")
                if application.identifier == 're.frida.Gadget':
                    target_name = 'Gadget'
                else:
                    target_name = application.identifier
            else:
                print("[*] No frontmost application found, will attach to all matching processes")
                target_name = None
        except Exception as e:
            print(f"[*] Could not get frontmost application: {e}")
            target_name = None
        
        print("[*] Enumerating processes...")
        processes = device.enumerate_processes()
        print(f"[*] Found {len(processes)} processes")
        
        attached_count = 0
        for process in processes:
            if target_name is None or target_name in process.name or (target_app and target_app.pid == process.pid):
                try:
                    _attach(process.pid)
                    attached_count += 1
                except Exception as e:
                    print(f"[*] Failed to attach to {process.name} ({process.pid}): {e}")
        
        print(f"[*] Successfully attached to {attached_count} processes")
        if attached_count == 0:
            app.log("No processes were attached. Check if the target app is running.")
            print("[!] No processes were attached. Check if the target app is running.")
                    
    except Exception as e:
        error_msg = f"Error starting trace: {str(e)}"
        app.log(error_msg)
        print(error_msg)


def stop_trace(app):
    global scripts
    print(f"[*] Unloading {len(scripts)} scripts...")
    for s in copy(scripts):
        try:
            s.unload()
            msg = "Trace script unloaded"
            app.log(msg)
            print(f"[*] {msg}")
        except Exception as e:
            error_msg = f"Error unloading script: {str(e)}"
            app.log(error_msg)
            print(f"[!] {error_msg}")
        scripts.remove(s)
    print("[*] All scripts unloaded")


class ZenTracerWindow(QMainWindow):
    app = None  # type: ZenTracer

    def __init__(self, app):
        super().__init__()
        self.app = app
        QtCore.QTimer.singleShot(100, self.setupContextMenu)

    def setupContextMenu(self):
        """设置右键菜单"""
        try:
            self.tree_context_menu = QMenu(self)
            self.copy_tree_action = QAction("Copy", self)
            self.copy_tree_action.triggered.connect(self.copyTreeSelection)
            self.tree_context_menu.addAction(self.copy_tree_action)
            
            self.resize_columns_action = QAction("Auto Resize Columns", self)
            self.resize_columns_action.triggered.connect(self.autoResizeColumns)
            self.tree_context_menu.addAction(self.resize_columns_action)
            
            self.list_context_menu = QMenu(self)
            self.copy_list_action = QAction("Copy", self)
            self.copy_list_action.triggered.connect(self.copyListSelection)
            self.list_context_menu.addAction(self.copy_list_action)
            
            if hasattr(self.app.ui, 'treeView') and self.app.ui.treeView:
                self.app.ui.treeView.customContextMenuRequested.connect(self.showTreeContextMenu)
            if hasattr(self.app.ui, 'logList') and self.app.ui.logList:
                self.app.ui.logList.customContextMenuRequested.connect(self.showListContextMenu)
                
            if hasattr(self.app.ui, 'treeView') and self.app.ui.treeView:
                self.app.ui.treeView.keyPressEvent = self.treeViewKeyPressEvent
            if hasattr(self.app.ui, 'logList') and self.app.ui.logList:
                self.app.ui.logList.keyPressEvent = self.logListKeyPressEvent
                
            print("[*] Copy support initialized")
            
        except Exception as e:
            print(f"[!] Error setting up context menu: {e}")

    def autoResizeColumns(self):
        """自动调整列宽"""
        try:
            if hasattr(self.app.ui, 'treeView') and self.app.ui.treeView:
                self.app.ui.treeView.header().setSectionResizeMode(QHeaderView.ResizeToContents)
                QtCore.QTimer.singleShot(50, lambda: self.app.ui.treeView.header().setSectionResizeMode(0, QHeaderView.Interactive))
                print("[*] Columns auto-resized")
        except Exception as e:
            print(f"[!] Error resizing columns: {e}")

    def treeViewKeyPressEvent(self, event):
        """处理TreeView键盘事件"""
        if event.key() == QtCore.Qt.Key_C and event.modifiers() == QtCore.Qt.ControlModifier:
            self.copyTreeSelection()
        elif event.key() == QtCore.Qt.Key_R and event.modifiers() == QtCore.Qt.ControlModifier:
            self.autoResizeColumns()
        else:
            QTreeView.keyPressEvent(self.app.ui.treeView, event)

    def logListKeyPressEvent(self, event):
        """处理ListView键盘事件"""
        if event.key() == QtCore.Qt.Key_C and event.modifiers() == QtCore.Qt.ControlModifier:
            self.copyListSelection()
        else:
            QListView.keyPressEvent(self.app.ui.logList, event)

    def showTreeContextMenu(self, position):
        """显示TreeView右键菜单"""
        self.tree_context_menu.exec_(self.app.ui.treeView.mapToGlobal(position))

    def showListContextMenu(self, position):
        """显示ListView右键菜单"""
        self.list_context_menu.exec_(self.app.ui.logList.mapToGlobal(position))

    def copyTreeSelection(self):
        """复制TreeView选中的内容"""
        try:
            selected_indexes = self.app.ui.treeView.selectedIndexes()
            if not selected_indexes:
                return
                
            rows_data = {}
            for index in selected_indexes:
                row = index.row()
                column = index.column()
                if row not in rows_data:
                    rows_data[row] = {}
                text = self.app.ui.treeView.model().data(index, QtCore.Qt.DisplayRole) or ""
                rows_data[row][column] = text
            
            copied_text = ""
            for row in sorted(rows_data.keys()):
                row_data = rows_data[row]
                row_text = []
                for col in sorted(row_data.keys()):
                    row_text.append(str(row_data[col]))
                copied_text += "\t".join(row_text) + "\n"
            
            clipboard = QApplication.clipboard()
            clipboard.setText(copied_text.strip())
            print("[*] Tree selection copied to clipboard")
            
        except Exception as e:
            print(f"[!] Error copying tree selection: {e}")

    def copyListSelection(self):
        """复制ListView选中的内容"""
        try:
            selected_indexes = self.app.ui.logList.selectedIndexes()
            if not selected_indexes:
                return
                
            copied_text = ""
            for index in selected_indexes:
                text = self.app.ui.logList.model().data(index, QtCore.Qt.DisplayRole) or ""
                copied_text += text + "\n"
            
            clipboard = QApplication.clipboard()
            clipboard.setText(copied_text.strip())
            print("[*] Logs copied to clipboard")
            
        except Exception as e:
            print(f"[!] Error copying list selection: {e}")

    def start_onClick(self):
        global scripts
        if scripts:
            stop_trace(self.app)
            self.app.ui.actionStart.setText("Start")
            scripts.clear()
            print("[*] Tracing stopped")
        else:
            print("[*] Starting trace...")
            threading.Thread(target=start_trace, args=(self.app,), daemon=True).start()
            self.app.ui.actionStart.setText("Stop")

    def clean_onClick(self):
        model = self.app.ui.treeView.model()
        if model:
            model.removeRows(0, model.rowCount())
        self.app.thread_map = {}
        print("[*] UI cleaned")

    def about_onClick(self):
        QMessageBox.about(self, "About",
                         "ZenTracer: Enhanced Android Tracer based-on frida \nAuthor: github.com/hluwa\n"
                         "Enhanced with r0tracer features\n"
                         "Frida Version: 16.4.2\n"
                         "Features: Better column alignment, auto-resize, copy support")

    def import_jobf_onClick(self):
        jobfile, _ = QFileDialog.getOpenFileName(self, 'Import jadx job file', '', 'Job file (*.jobf)')
        if not jobfile:
            return
        
        try:
            with open(jobfile, 'r', encoding='utf-8') as f:
                jobbody = f.read()
            
            cls_maps = {}
            for t in jobbody.splitlines():
                if t.startswith('c '):
                    parts = t[2:].split(' = ')
                    if len(parts) == 2:
                        src, dest = parts
                        pkg = src[:src.rfind('.') + 1]
                        cls = src[src.rfind('.') + 1:]
                        if "$" in cls:
                            pkg += cls[:cls.rfind('$') + 1]
                            cls = cls[cls.rfind('$') + 1:]
                        cls_maps[pkg + cls] = pkg + dest
            
            updated_count = 0
            for tid in self.app.thread_map:
                for item in self.app.thread_map[tid]['list']:
                    if isinstance(item, TraceItem) and item.clazz in cls_maps:
                        item.clazz = cls_maps[item.clazz]
                        item.method_item.setText(item._format_method_text())
                        updated_count += 1
            
            print(f"[*] Updated {updated_count} class names from job file")
            self.app.log(f"Updated {updated_count} class names from job file")
                        
        except Exception as e:
            error_msg = f"Failed to import job file: {str(e)}"
            QMessageBox.warning(self, "Error", error_msg)
            print(f"[!] {error_msg}")

    def black_onClick(self):
        self.app.black_regex_dialog.show()
        print("[*] Opening black regex dialog")

    def match_onClick(self):
        self.app.match_regex_dialog.show()
        print("[*] Opening match regex dialog")

    def export_onClick(self):
        jobfile, _ = QFileDialog.getSaveFileName(self, 'Export', '', 'JSON file (*.json)')
        if not jobfile:
            return
        
        try:
            export = {
                'match_regex': self.app.match_regex_list,
                'black_regex': self.app.black_regex_list,
                'tree': {}
            }
            
            for tid in self.app.thread_map:
                thread_info = self.app.thread_map[tid]
                if thread_info['list']:
                    tree_key = thread_info['list'][0].method_item.text()
                    export['tree'][tree_key] = gen_tree(thread_info['list'][0])
            
            with open(jobfile, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=2)
            
            print(f"[*] Data exported to {jobfile}")
            self.app.log(f"Data exported to {jobfile}")
                
        except Exception as e:
            error_msg = f"Failed to export: {str(e)}"
            QMessageBox.warning(self, "Error", error_msg)
            print(f"[!] {error_msg}")

    def import_onClick(self):
        jobfile, _ = QFileDialog.getOpenFileName(self, 'Import', '', 'JSON file (*.json)')
        if not jobfile:
            return
        
        try:
            with open(jobfile, 'r', encoding='utf-8') as f:
                export = json.load(f)
            
            self.app.match_regex_list.clear()
            self.app.black_regex_list.clear()
            self.clean_onClick()
            
            if 'match_regex' in export:
                self.app.match_regex_list.extend(export['match_regex'])
                self.app.match_regex_dialog.setupList()
                print(f"[*] Imported {len(export['match_regex'])} match regex patterns")
                
            if 'black_regex' in export:
                self.app.black_regex_list.extend(export['black_regex'])
                self.app.black_regex_dialog.setupList()
                print(f"[*] Imported {len(export['black_regex'])} black regex patterns")
            
            tree_count = 0
            if 'tree' in export:
                for thread_key in export['tree']:
                    parts = thread_key.split(' - ', 1)
                    tid = parts[0] if len(parts) > 0 else "unknown"
                    tname = parts[1] if len(parts) > 1 else "unknown"
                    for item in export['tree'][thread_key]:
                        put_tree(self.app, tid, tname, item)
                        tree_count += 1
                
                print(f"[*] Imported {tree_count} method calls from {len(export['tree'])} threads")
                self.app.log(f"Imported {tree_count} method calls")
                        
        except Exception as e:
            error_msg = f"Failed to import: {str(e)}"
            QMessageBox.warning(self, "Error", error_msg)
            print(f"[!] {error_msg}")


def put_tree(app, tid, tname, item):
    if 'clazz' in item and 'method' in item:
        app.method_entry(tid, tname, item['clazz'], item['method'], item.get('args', ''))
        for child in item.get('child', []):
            put_tree(app, tid, tname, child)
        app.method_exit(tid, item.get('retval', ''))


def gen_tree(item):
    if hasattr(item, 'clazz') and hasattr(item, 'method'):
        res = {
            'clazz': item.clazz,
            'method': item.method,
            'args': item.args,
            'child': [],
            'retval': item.retval
        }
        for child_item in item.child_items:
            res['child'].append(gen_tree(child_item))
        return res
    else:
        return {}


class ZenTracer:
    def __init__(self):
        global APP
        APP = self
        
        print("[*] Starting Enhanced ZenTracer...")
        print(f"[*] Python version: {sys.version}")
        print(f"[*] Frida version: {frida.__version__}")
        
        self.app = QApplication(sys.argv)
        self.ui = Ui_MainWindow()
        self.window = ZenTracerWindow(self)
        
        try:
            self.window.setWindowIcon(QIcon('icon.png'))
        except:
            print("[!] Could not load icon.png")
        
        self.ui.setupUi(self.window)
        self.setupAction()
        self.setupTreeModel()
        self.thread_map = {}
        self.black_regex_list = []
        self.match_regex_list = []
        self.black_regex_dialog = ListWindow(self.black_regex_list, "Black RegEx")
        self.match_regex_dialog = ListWindow(self.match_regex_list, "Match RegEx")
        self.window.show()
        
        print("[*] Enhanced ZenTracer GUI initialized successfully")
        print("[*] Ready to start tracing")
        print("[*] Copy support enabled: Use Ctrl+C or right-click to copy selected items")
        print("[*] Auto-resize columns: Use Ctrl+R or right-click -> 'Auto Resize Columns'")
        print("[*] Enhanced tracing features: call stack, field inspection, better argument handling")
        
        QtCore.QTimer.singleShot(100, lambda: self.ui.logList.scrollToBottom())
        
        sys.exit(self.app.exec_())

    def setupAction(self):
        self.ui.actionAbout.triggered.connect(self.window.about_onClick)
        self.ui.actionBlack_Regex.triggered.connect(self.window.black_onClick)
        self.ui.actionMatch_Regex.triggered.connect(self.window.match_onClick)
        self.ui.actionStart.triggered.connect(self.window.start_onClick)
        self.ui.actionClean.triggered.connect(self.window.clean_onClick)
        self.ui.actionExportJSON.triggered.connect(self.window.export_onClick)
        self.ui.actionImportJSON.triggered.connect(self.window.import_onClick)

    def setupTreeModel(self):
        self.ui.logList.setModel(QStandardItemModel(self.ui.logList))
        model = QStandardItemModel(self.ui.treeView)
        model.setHorizontalHeaderLabels(['Method', 'Arguments', 'Return Value'])
        self.ui.treeView.setModel(model)
        
        header = self.ui.treeView.header()
        self.ui.treeView.setColumnWidth(0, 400)
        self.ui.treeView.setColumnWidth(1, 350)
        self.ui.treeView.setColumnWidth(2, 300)
        
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        
        self.ui.treeView.setAlternatingRowColors(True)
        
        font = self.ui.treeView.font()
        font.setFamily("Courier New")
        self.ui.treeView.setFont(font)

    def method_entry(self, tid, tname, clazz, method, args):
        if tid not in self.thread_map:
            # 创建线程根节点
            thread_method_item = QStandardItem(f'{tid} - {tname}')
            thread_args_item = QStandardItem("")
            thread_retval_item = QStandardItem("")
            
            thread_method_item.setEditable(False)
            thread_args_item.setEditable(False)
            thread_retval_item.setEditable(False)
            
            self.ui.treeView.model().appendRow([thread_method_item, thread_args_item, thread_retval_item])
            
            # 为线程根节点创建一个特殊的TraceItem
            thread_trace_item = TraceItem("Thread", f"{tid}-{tname}", "", None)
            thread_trace_item.method_item = thread_method_item
            thread_trace_item.args_item = thread_args_item
            thread_trace_item.retval_item = thread_retval_item
            
            self.thread_map[tid] = {
                'stack': [thread_trace_item],  # 调用栈，栈顶是当前活动的方法
                'root_item': thread_trace_item,  # 线程根节点
                'list': [thread_trace_item]  # 线程中的所有TraceItem
            }
        
        thread_info = self.thread_map[tid]
        
        # 获取当前栈顶项作为父项
        parent_item = thread_info['stack'][-1] if thread_info['stack'] else thread_info['root_item']
        
        # 创建新的TraceItem
        trace_item = TraceItem(clazz, method, args, parent_item.method_item)
        
        # 将新项添加到调用栈和列表中
        thread_info['stack'].append(trace_item)
        thread_info['list'].append(trace_item)
        
        # 自动展开新添加的项目
        index = self.ui.treeView.model().indexFromItem(trace_item.method_item)
        self.ui.treeView.expand(index)
        
        # 更新父项的child_items
        parent_item.child_items.append(trace_item)

    def method_exit(self, tid, retval):
        if tid in self.thread_map:
            thread_info = self.thread_map[tid]
            
            if len(thread_info['stack']) > 1:  # 确保栈中至少有一个方法（不包括线程根节点）
                # 弹出当前项
                current_item = thread_info['stack'].pop()
                
                # 设置返回值
                current_item.set_retval(retval)
                
                print(f"[*] Set return value for {current_item.clazz}.{current_item.method}: {retval}")

    def log(self, text):
        """记录日志到GUI和终端"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        gui_text = f"{timestamp}:  [*] {text}"
        
        model = self.ui.logList.model()
        if model:
            item = QStandardItem(gui_text)
            item.setEditable(False)
            model.insertRow(0, item)
            self.ui.logList.scrollToBottom()


if __name__ == '__main__':
    ZenTracer()