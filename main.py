#!/usr/bin/env python3

from PyQt5 import uic, QtCore
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QTableWidget, QTableWidgetItem, QLineEdit, QHeaderView, QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
import json
import urllib.request
import subprocess
import sys

keys = ["Delete", "subname", "type", "records", "ttl", "name", "touched", "created" ]

class Ui(QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi('mainwindow.ui', self)
        self.show()
        self.txt_pw.setEchoMode(QLineEdit.Password)
        self.txt_token.setEchoMode(QLineEdit.Password)
        self.btn_list_dom.pressed.connect(self.fn_load_all_registerd_domains)
        self.btn_login.pressed.connect(self.fn_login)
        self.btn_save.pressed.connect(self.write_table_to_file)
        self.btn_toggle_token.pressed.connect(self.fn_toggle_token)
        self.btn_comp.pressed.connect(self.fn_user_compare)
        self.btn_upload.pressed.connect(self.upload)
        self.btn_clear.pressed.connect(self.fn_clear_log)
        self.btn_newentry.pressed.connect(self.fn_newentry)
        self.btn_load.pressed.connect(self.load_json_into_table)
        self.com_dom.currentIndexChanged.connect(self.fn_change_domain)
        self.token = ""
        self.current_domain = 0
        self.domains = []
        self.all_rrsets = []
        self.tbl_rrsets = [[],[],[],[],[]]
        self.json_file = []

    def closeEvent(self, event):
        reply = QMessageBox.question(self, 'Message',
            "Are you sure to quit an logout?", QMessageBox.Yes, QMessageBox.No)

        if reply == QMessageBox.Yes:
            response = self.url_cmd("https://desec.io/api/v1/auth/logout/", self.header, 0, 'POST')
            if response == 1:
                return 1
            event.accept()
        else:
            event.ignore()

    def fn_toggle_token(self):
        if self.txt_token.echoMode() == QLineEdit.Password:
            self.txt_token.setEchoMode(QLineEdit.Normal)
        else:
            self.txt_token.setEchoMode(QLineEdit.Password)

    def populate(self, set):
        try: self.table_widget.itemChanged.disconnect()
        except Exception: pass
        nrows, ncols = len(set[self.current_domain]), len(keys)
        self.table_widget.setSortingEnabled(False)
        self.table_widget.setRowCount(nrows)
        self.table_widget.setColumnCount(ncols)
        self.table_widget.setHorizontalHeaderLabels(keys)
        tbl_header = self.table_widget.horizontalHeader()
        tbl_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        tbl_header.setSectionResizeMode(3, QHeaderView.Stretch) 
        for i in range(nrows):
            for j in range(ncols):
                self.table_widget.setItem(i, j, self.pop_row(set, i, j))
        self.table_widget.setSortingEnabled(True)
        self.table_widget.itemChanged.connect(self.fn_tbl_edit)

    def pop_row(self, set, row, col):
        if col == 0:
            item = QTableWidgetItem()
            item.setFlags(QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
            item.setCheckState(QtCore.Qt.Unchecked)
        else:
            if set == 0:
                element = ""
            else:
                element = set[self.current_domain][row][keys[col]]
            if isinstance(element, list):
                element = ','.join(element)
            item = QTableWidgetItem(str(element))
        item.setTextAlignment(Qt.AlignCenter)
        return item

    def fn_tbl_edit(self):
        self.save_table_into_json() 

    def fn_newentry(self):
        self.save_table_into_json()
        self.table_widget.itemChanged.disconnect()
        self.table_widget.setSortingEnabled(False)
        row = self.table_widget.rowCount()
        self.table_widget.setRowCount(row+1)
        for i in range(0, 9):
            self.table_widget.setItem(row, i, self.pop_row(0, row, i))
        self.table_widget.setSortingEnabled(True)
        self.table_widget.itemChanged.connect(self.fn_tbl_edit)
        self.save_table_into_json() 

    def compare(self):
        local = self.dep(self.tbl_rrsets[self.current_domain])
        server = self.dep(self.all_rrsets[self.current_domain])
        temp_local = local
        self.deleted = server
        no_change = []
        self.change = []
        self.new_rrset = []
        while temp_local:
            tmp_set = temp_local.pop(0)
            for index, item in enumerate(server):
                if item["subname"] == tmp_set["subname"]:
                    if item["type"] == tmp_set["type"]:
                        self.deleted.pop(index)
                        if item["records"] == tmp_set["records"]  and str(item["ttl"]) == str(tmp_set["ttl"]):
                            no_change.append(tmp_set)
                            tmp_set = ""
                            break
                        else:
                            self.change.append(tmp_set)
                            tmp_set = ""
                            break
            if tmp_set != "":
                self.new_rrset.append(tmp_set)

    def fn_user_compare(self):
        self.compare()
        self.txt_log.appendPlainText("New RRsets:")
        self.txt_log.appendPlainText(str(self.new_rrset))
        self.txt_log.appendPlainText("Deleted RRset")
        self.txt_log.appendPlainText(str(self.deleted))
        self.txt_log.appendPlainText("Changed RRset")
        self.txt_log.appendPlainText(str(self.change))

    def fn_clear_log(self):
        self.txt_log.setPlainText("")

    def upload(self):
        self.save_table_into_json()
        self.compare()
        upload_set = self.new_rrset
        upload_set.extend(self.change)
        deleted = self.deleted
        for item in deleted:
            item["records"] = []
        upload_set.extend(deleted)
        if not upload_set:
            self.txt_log.appendPlainText("No changes made. Not uploading anything")
            return
        header = { "Authorization" : "Token " + self.token,  "Content-Type" : "application/json"}
        response = self.url_cmd("https://desec.io/api/v1/domains/" + self.domains[self.current_domain] + "/rrsets/", header, upload_set, 'PATCH')
        if response == 1:
            return
        self.txt_log.appendPlainText("Uploading new entries")
        self.fn_load_all_registerd_domains()

    def url_cmd(self, url, header, data=0, method='PATCH'):
        req = urllib.request.Request(url, None, header, None, False, method)
        try:
            if data == 0:
                response = urllib.request.urlopen(req)
            else:
                response = urllib.request.urlopen(req, json.dumps(data).encode('utf-8'))
        except urllib.error.HTTPError as e:
            self.txt_log.appendPlainText("HTTP status code: " + str(e.code))
            self.txt_log.appendPlainText(str(e.read().decode()))
            #self.txt_log.appendPlainText( str( json.loads( e.read() )["detail"] ) )
            #print(json.loads( e.read() )["detail"])
            return 1
        self.txt_log.appendPlainText("HTTP status code: " + str(response.code))
        return response

    #Shrink JSON to fields we compare
    def dep(self, json_set):
        dep_dom = []
        for i in range(len(json_set)):
            dep_dom_row = {}
            for j in range(1, 5):
                dep_dom_row[keys[j]] = json_set[i][keys[j]]
            dep_dom.append(dep_dom_row)
        return dep_dom

    def save_table_into_json(self):
        nrows, ncols = self.table_widget.rowCount(), len(keys)
        self.tbl_rrsets[self.current_domain] = []
        for i in range(nrows):
            if self.table_widget.item(i,0).checkState() == Qt.Checked:
                continue
            self.tbl_rrsets_row = {}
            for j in range(ncols):
                if j == keys.index("records"):
                    self.tbl_rrsets_row[keys[j]] = self.table_widget.item(i,j).text().split(',')
                elif j == keys.index("Delete"):
                    continue
                else:
                    self.tbl_rrsets_row[keys[j]] = self.table_widget.item(i,j).text()
            self.tbl_rrsets[self.current_domain].append(self.tbl_rrsets_row)   
        self.draw_window(self.tbl_rrsets)

    def write_table_to_file(self):
        save_dialog = QFileDialog()
        save_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_path = save_dialog.getSaveFileName(self, 'Save as... File', './', filter='JASON Files(*.json)')
        json_save_file = open(file_path[0], "w+")
        for index, domain in enumerate(self.domains):
            temp = {}
            temp["domain"] = domain
            temp["rrsets"] = self.tbl_rrsets[index]
            self.json_file.append(temp)
        json_save_file.write(json.dumps(self.json_file, indent=4, sort_keys=True))
        json_save_file.close()
        self.txt_log.appendPlainText("Aved successfully")

    def load_json_into_table(self):
        file_path = QFileDialog.getOpenFileName(self, 'Open File')
        json_save_file = open(file_path[0], "r")
        json_save_file = json.load(json_save_file)
        for domain in json_save_file:
            for index_server, domain_server in enumerate(self.domains):
                if domain_server == domain["domain"]:
                    self.tbl_rrsets[index_server] = domain["rrsets"]
        self.draw_window(self.tbl_rrsets)

    def update_table(self):
        self.table_widget.sortItems(1,QtCore.Qt.AscendingOrder)

    def fn_login(self):
        if (self.txt_token.text() != ""):
            self.txt_log.appendPlainText("Trying to login with token...")
            self.token = self.txt_token.text()
            self.header = { "Authorization" : "Token " + self.token }
            res = self.fn_load_all_registerd_domains()
            if res == 1:
                self.txt_log.appendPlainText("Token not working...")
                self.txt_log.appendPlainText("Retry or clear token field and fetch a new one with your credentials")  
        else:
            if not self.get_token():
                self.fn_login()
                

    def get_token(self):
        header = { "Content-Type" : "application/json"}
        auth_data = { "email" : self.txt_email.text(), "password" : self.txt_pw.text() }
        response = self.url_cmd("https://desec.io/api/v1/auth/login/", header, auth_data, 'POST')
        if response == 1:
            self.txt_log.appendPlainText("Can not login to get token...")
            return 1
        self.json_auth = json.loads(response.read())
        self.token = self.json_auth["token"]
        self.txt_token.setText(str(self.token))
        self.txt_log.appendPlainText("Fetched token")
        return 0

    def draw_window(self, set):
        self.txt_created.setText(self.json_domains[self.current_domain]["created"])
        self.txt_published.setText(self.json_domains[self.current_domain]["published"])
        self.txt_touched.setText(self.json_domains[self.current_domain]["touched"])
        self.populate(set)
        self.update_table()

    def fn_change_domain(self):
        self.save_table_into_json()
        self.current_domain = self.com_dom.currentIndex()
        self.draw_window(self.tbl_rrsets)

    def fn_load_all_registerd_domains(self):
        response = self.url_cmd("https://desec.io/api/v1/domains/", self.header, 0, 'GET')
        if response == 1:
            return 1
        self.json_domains = json.loads(response.read())
        self.domains = []
        for domain in self.json_domains:
            self.domains.append(domain["name"])
        self.com_dom.clear()
        self.com_dom.addItems(self.domains)
        self.fn_load_rrsets()
        self.txt_log.appendPlainText("Loaded entries from nameserver")

    def fn_load_rrsets(self):
        self.all_rrsets = []
        for index, item in enumerate(self.domains):
            response = self.url_cmd("https://desec.io/api/v1/domains/" + item + "/rrsets/", self.header, 0, 'GET')
            if response == 1:
                return
            self.json_rrsets = json.loads(response.read())
            self.all_rrsets.append(self.json_rrsets)
            self.com_dom.setCurrentIndex(index)
            self.draw_window(self.all_rrsets)
            self.save_table_into_json()

def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

app = QApplication(sys.argv)
window = Ui()
app.exec_()