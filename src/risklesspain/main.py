#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  Copyright 2025 Tobias Ospelt <tobias@pentagrid.ch>
#
import copy
import difflib
import hashlib
import importlib.metadata
import json
import os
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Optional, Tuple
from xml.etree.ElementTree import Element

from PyQt6 import QtCore, QtGui, uic, QtWidgets
from lxml import etree
from lxml.etree import XMLSchema

from risklesspain.PyQtGuiLoggingHandler import PyQtGuiLoggingHandler
from risklesspain.loggingsetup import LoggingFormatter

# qt_handler = PyQtGuiLoggingHandler(main_window)
# qt_handler.setLevel(logging.INFO)
# qt_handler.setFormatter(LoggingFormatter(disable_color=True))
#
# logging_command_line_handler = logging.StreamHandler(sys.stdout)
# logging_command_line_handler.setLevel(logging.DEBUG)
# logging_command_line_handler.setFormatter(LoggingFormatter())

# logging.basicConfig(level=logging.DEBUG, handlers=[logging_command_line_handler, qt_handler])
# logging.basicConfig(level=logging.INFO, handlers=[logging_command_line_handler, qt_handler])

logging.basicConfig(level=logging.DEBUG)

# logging_command_line_handler.setLevel(logging.DEBUG)
# qt_handler.setLevel(logging.INFO)



TABLE_HEADERS = ["Index", "IBAN/Othr", "Name", "Town/Country", "Currency", "Amount", "Bank Identifiers", "XML identical", "Status"]

IDENTICAL_TRANSACTION = "Identical transaction"  # No color
MODIFIED_TRANSACTION = "Modified transaction"  # modified fields in orange
NEW_TRANSACTION = "New transaction"  # Green
OLD_TRANSACTION = "Old transaction (not in new file)"  # Red

NAMESPACE_03_CH_02 = "{http://www.six-interbank-clearing.com/de/pain.001.001.03.ch.02.xsd}"

SPEC_AND_NAMESPACE: (str, str) = [
    # Swiss standards
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.03.ch.02.xsd")), NAMESPACE_03_CH_02),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.09.ch.03.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.09}"),
    # International standards
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.01.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.01}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.02.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.02}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.03.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.03}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.04.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.04}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.07.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.07}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.08.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.08}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.09.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.09}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.10.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.10}"),
    (os.path.join(os.path.dirname(__file__), os.path.join("spec","pain.001.001.11.xsd")), "{urn:iso:std:iso:20022:tech:xsd:pain.001.001.11}"),
]

@dataclass
class Pain001Specification:
    file_path: str = ""
    namespace: str = ""
    spec_name: str = ""
    schema: XMLSchema = None

@dataclass
class Transaction:
    currency: str = "UNKNOWN"
    amount: str = ""
    bank_identifier: str = "UNKNOWN"
    name: str = "UNKNOWN"
    town_country: str = "UNKNOWN"
    iban_othr: str = "UNKNOWN"
    hash_value: str = ""
    xml_tree_element_str: str = ""
    status: str = ""


@dataclass
class PainContent:
    file_path: str = None
    pain_xml_content: bytes = None
    specification: Pain001Specification = None
    transactions: list[Transaction] = field(default_factory=list)

class NotExactlyOneElementException(Exception):
    pass

def direct_multi_child_text(tree: Element, child_name: str) -> str:
    texts = [elem.text for elem in get_direct_and_any_number_of_childs(tree, child_name)]
    texts.sort()
    return " / ".join(texts)

def get_direct_and_any_number_of_childs(tree: Element, child_name: str) -> list[Element]:
    elements = [elem for elem in list(tree) if elem.tag == f"{child_name}"]
    elements.sort()
    return elements

def direct_single_child(tree: Element, child_name: str) -> Element:
    all_matching = [elem for elem in list(tree) if elem.tag == f"{child_name}"]
    if len(all_matching) != 1:
        raise NotExactlyOneElementException(f"There were {len(all_matching)} elements of type {child_name}")
    else:
        return all_matching[0]

def prepare_table_before_inserting(t):
    old_sort = t.horizontalHeader().sortIndicatorSection()
    old_order = t.horizontalHeader().sortIndicatorOrder()
    t.setSortingEnabled(False)
    return old_sort, old_order

def perform_followup_on_table_after_inserting(t, old_sort, old_order):
    t.sortItems(old_sort, old_order)
    t.setSortingEnabled(True)

def xor_hex_string_halves(hex_string: str) -> str:
    n = len(hex_string)
    xs, ys = hex_string[0:n//2], hex_string[n//2:n]
    return hex(int(xs, 16) ^ int(ys, 16)).upper()[2:]

class MainWindow(QtWidgets.QMainWindow):
    load_file_test_signal = QtCore.pyqtSignal(list)
    clear_test_signal = QtCore.pyqtSignal()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        print(os.listdir(os.path.dirname(__file__)))
        uic.loadUi(os.path.join(os.path.dirname(__file__), "ui", "main_window.ui"), self)
        logging.info("Initializing")

        # settings
        QtCore.QCoreApplication.setOrganizationName("Pentagrid")
        QtCore.QCoreApplication.setOrganizationDomain("pentagrid.ch")
        QtCore.QCoreApplication.setApplicationName(f"Riskless Pain GUI" + importlib.metadata.version('risklesspain'))

        # menu bar
        # noinspection PyUnresolvedReferences
        self.mb_action_about.triggered.connect(self.about)
        # noinspection PyUnresolvedReferences
        self.mb_action_quit.triggered.connect(self.exit_app)

        # tab 1
        # noinspection PyUnresolvedReferences
        self.pb_clear.clicked.connect(self.clear_and_forget)
        # noinspection PyUnresolvedReferences
        self.pb_clear_and_forget.clicked.connect(self.clear_and_forget_history)
        # noinspection PyUnresolvedReferences
        self.pb_select_pain_file.clicked.connect(self.select_pain_file)
        # noinspection PyUnresolvedReferences
        self.tw_payments_table.itemSelectionChanged.connect(self.project_selection_changed)
        # noinspection PyUnresolvedReferences
        self.tw_payments_table.doubleClicked.connect(self.fill_differences)

        self.settings = QtCore.QSettings('Pentagrid', 'RisklessPain')

        self.parser = etree.XMLParser(remove_blank_text=True)

        self.specifications: list[Pain001Specification] = []
        for spec_file_path, namespace in SPEC_AND_NAMESPACE:
            with open(spec_file_path, "r", encoding="utf-8") as xsd:
                print(f"Parsing {spec_file_path}")
                xmlschema_doc = etree.parse(xsd, self.parser)
                spec_name = os.path.basename(os.path.splitext(spec_file_path)[0])
                self.specifications.append(Pain001Specification(spec_file_path, namespace, spec_name, etree.XMLSchema(xmlschema_doc)))

        self.load_file_test_signal.connect(self.load_files)
        self.clear_test_signal.connect(self.clear_table)

        self.last_file: Optional[PainContent] = None
        self.loaded_transaction_tuples: list[Tuple[Transaction, Transaction]] = []

        document = self.label_differences.document()
        font = document.defaultFont()
        font.setFamily("Courier New")
        document.setDefaultFont(font)

        if self.settings.value("last_file"):
            try:
                last_file_dict = json.loads(self.settings.value("last_file"))
                file_path = last_file_dict["file_path"]
                logging.debug(f"Read out from seetings file_path: {file_path}")
                spec_name = last_file_dict["spec_name"]
                logging.debug(f"Read out from seetings spec_name: {spec_name}")
                xml_content = last_file_dict["xml_content"].encode()
                logging.debug(f"Read out from seetings xml_content: {xml_content}")
                for spec in self.specifications:
                    if spec.spec_name == spec_name:
                        self.last_file = PainContent(file_path, xml_content, spec)
                        self.parse_transactions(self.last_file)
                        break
                else:
                    logging.warning(f"Couldn't find spec {spec_name}!")
            except (KeyError, ValueError, TypeError) as e:
                self.clear_and_forget()
                logging.warning(f"Couldn't use last file! {e}")
            else:
                self.process_files([])  # The process_files already adds the last_file
                logging.debug(f"Successfully read {self.last_file.file_path} from settings")

    def get_selected_transaction_index(self) -> int:
        try:
            # noinspection PyUnresolvedReferences
            row = self.tw_payments_table.currentItem().row()
            # noinspection PyUnresolvedReferences
            first_column_value_str = self.tw_payments_table.item(row, 0).text()
            transaction_index = int(first_column_value_str) - 1
        except (AttributeError, ValueError):
            transaction_index = -1
        return transaction_index

    def fill_differences(self):
        if self.loaded_transaction_tuples:
            index = self.get_selected_transaction_index()
            if index >= 0:
                old_transaction, new_transaction = self.loaded_transaction_tuples[index]
                if old_transaction and new_transaction:
                    logging.debug(old_transaction.xml_tree_element_str)
                    logging.debug(new_transaction.xml_tree_element_str)
                    diff_text = ''.join(difflib.ndiff(old_transaction.xml_tree_element_str.splitlines(keepends=True), new_transaction.xml_tree_element_str.splitlines(keepends=True)))
                    # noinspection PyUnresolvedReferences
                    self.label_differences.setText(f"Difference between transaction with table ID {index + 1} and it's best match old version (PmtId tag if present was removed):\n\n{diff_text}")
                    self.tabWidget.setCurrentIndex(1)
                elif new_transaction:
                    # Only show new transaction
                    self.label_differences.setText(f"Content of new transaction with table ID {index + 1} (PmtId tag if present was removed):\n\n{new_transaction.xml_tree_element_str}")
                    self.tabWidget.setCurrentIndex(1)
                elif old_transaction:
                    # Only show new transaction
                    self.label_differences.setText(f"Content of old transaction with table ID {index + 1} (PmtId tag if present was removed!):\n\n{old_transaction.xml_tree_element_str}")
                    self.tabWidget.setCurrentIndex(1)
            else:
                logging.debug("Selected row index < 0")
                self.label_differences.setText("")
        else:
            logging.debug("loaded_transaction_tuples is empty")
            self.label_differences.setText("")

    def load_files(self, files: list[str]):
        self.process_files(self.validate_files(files))

    def project_selection_changed(self):
        pass

    def select_pain_file(self):
        dialog = QtWidgets.QFileDialog(self)
        dialog.setFileMode(QtWidgets.QFileDialog.FileMode.ExistingFiles)
        #dialog.setNameFilter("pain001 files (*.xml *.pain001)")
        if dialog.exec():
            file_paths = dialog.selectedFiles()
            valid_files: list[PainContent] = self.validate_files(file_paths)
            logging.info(f"Found {len(valid_files)} valid files.")
            self.process_files(valid_files)

    def validate_files(self, file_paths: list[str]) -> list[PainContent]:
        valid_files: list[PainContent] = []
        for file_path in file_paths:
            if os.path.exists(file_path) and os.path.isfile(file_path):
                with open(file_path, "rb") as pain:
                    pain_xml_content = pain.read()
                try:
                    # Here we are parsing an untrusted XML file. However, the no_network attribute
                    # is True by default, also no DTD loading or parsing, so this looks safe and was also
                    # tested according to test-files. However, please feel free to test this and
                    # report any security issues you can identify. DoS are not deemed critical enough
                    # as that would only lead to an out of memory/other resource situation which should
                    # be gracefully handled by any Desktop OS where a Python QT GUI is running.
                    # Do NOT use this project on a server, this is meant to be a client Desktop OS GUI.
                    # As we don't know which schema is applicable yet, we don't supply schema= here.
                    xml_tree = etree.parse(BytesIO(pain_xml_content), self.parser)
                except (etree.XMLSyntaxError, UnicodeDecodeError) as e:
                    MainWindow._popup_info_message("XML validation issue",
                                                   f"{file_path}\n\nDoes not seem to be a "
                                                   f"valid XML file at all\n\n"
                                                   f"{e}")
                    self.clear_and_forget()
                    continue
                for pain_specification in self.specifications:
                    if pain_specification.schema.validate(xml_tree) and pain_specification.spec_name in etree.tostring(xml_tree).decode():
                        pain_file = PainContent(file_path, pain_xml_content, pain_specification)
                        #logging.debug(pain_file)
                        break
                else:
                    specs = " or ".join((x.spec_name for x in self.specifications))
                    errors = ""
                    for pain_specification in self.specifications:
                        errors += f"{pain_specification.spec_name} errors:\n{pain_specification.schema.error_log}\n\n"
                    MainWindow._popup_info_message("XML validation issue",
                                                   f"Unfortunately this is not a "
                                                   f"valid {specs} XML file. "
                                                   f"This program only works with "
                                                   f"those files from the ISO 20022 standard yet. "
                                                   f"See https://pain001.com/pain.001.001.09/ or "
                                                   f"https://zahlungsverkehr.org/"
                                                   f"internationaler-zahlungsverkehr/"
                                                   f"iso-20022-standard/pain-001 (German) "
                                                   f"for examples and explanations.\n\n"
                                                   f"{errors}\n\n{file_path}")
                    self.clear_and_forget()
                    continue
                try:
                    self.parse_transactions(pain_file)
                    logging.info(f"{len(pain_file.transactions)} transactions found in {pain_file.file_path}")
                    if len(pain_file.transactions) == 0:
                        MainWindow._popup_info_message(f"No transactions", f"The pain001 has no transactions "
                                                                          f"in it. Please use another verification "
                                                                          f"method than this GUI and check the XML "
                                                                          f"manually.\n\n{pain_file.file_path}")
                        self.clear_and_forget()
                        continue
                except NotExactlyOneElementException as e:
                    MainWindow._popup_info_message("Transactions not parseable",
                                                   f"{file_path}\n\n"
                                                   f"There are missing or multiple fields for certain "
                                                   f"transactions elements. We do not support that:\n\n"
                                                   f"{e}")
                    self.clear_and_forget()
                    continue
                valid_files.append(pain_file)
            else:
                MainWindow._popup_info_message("File not found",
                                               f"{file_path}\n\n"
                                               f"This path does not exist or is not a file (directories "
                                               f"are not supported by this tool)")
                self.clear_and_forget()
                continue
        return valid_files

    def process_files(self, valid_files: list[PainContent]):
        if self.last_file:
            valid_files.insert(0, self.last_file)
        if not valid_files:
            return
        self.last_file = valid_files[-1]
        # Now store the last file in JSON settings
        last_file_dict = {
            "file_path": self.last_file.file_path,
            "spec_name": self.last_file.specification.spec_name,
            "xml_content": self.last_file.pain_xml_content.decode()
        }
        self.settings.setValue("last_file", json.dumps(last_file_dict))
        logging.debug(f"Stored setting, file_path: {self.last_file.file_path}, "
                      f"spec_name: {self.last_file.specification.spec_name}")
        logging.debug([x.file_path for x in valid_files])
        self.load_files_into_table(valid_files)

    def load_files_into_table(self, valid_files: list[PainContent]):
        # We always load the last two files
        if len(valid_files) == 1:
            self.load_file_into_table(valid_files[-1])
            self.statusBar().showMessage(f"Showing {os.path.basename(valid_files[-1].file_path)}")
        else:
            self.load_diff_of_files_into_table(valid_files[-2], valid_files[-1])
            self.statusBar().showMessage(f"New {os.path.basename(valid_files[-1].file_path)} compared to old {os.path.basename(valid_files[-2].file_path)}")

    def load_file_into_table(self, pain_file: PainContent):
        # noinspection PyUnresolvedReferences
        table = self.tw_payments_table
        self.clear_table()

        # This is the "manual" sort of the user, which should take precedence
        old_sort, old_order = prepare_table_before_inserting(table)

        table.setRowCount(len(pain_file.transactions))
        table.setColumnCount(len(TABLE_HEADERS))
        table.setHorizontalHeaderLabels(TABLE_HEADERS)

        self.loaded_transaction_tuples = [(None, x) for x in pain_file.transactions]

        i = 0

        for index, transaction in enumerate(pain_file.transactions):

            values_to_render = [index + 1, transaction.iban_othr, transaction.name, transaction.town_country,
                                transaction.currency, transaction.amount, transaction.bank_identifier,
                                "", transaction.status]

            j = 0
            for k in values_to_render:
                table.setItem(i, j, QtWidgets.QTableWidgetItem(str(k)))
                j += 1

            i += 1

        # restore order
        perform_followup_on_table_after_inserting(table, old_sort, old_order)

        table.resizeColumnsToContents()

    def load_diff_of_files_into_table(self, old_pain_file: PainContent, new_pain_file: PainContent):
        # noinspection PyUnresolvedReferences
        table = self.tw_payments_table
        self.clear_table()

        # Before we know the amount of items in the table, we have to do the diff
        old_transactions = copy.deepcopy(old_pain_file.transactions)
        new_transactions = copy.deepcopy(new_pain_file.transactions)

        transactions_tuples: list[Tuple[Transaction, Transaction]] = []

        for index, new_transaction in enumerate(new_transactions):
            old_transaction = self.pop_best_match(new_transaction, old_transactions)
            transactions_tuples.append((old_transaction, new_transaction))

        self.loaded_transaction_tuples = copy.deepcopy(transactions_tuples)
        self.loaded_transaction_tuples.extend([(x, None) for x in old_transactions])

        # This is the "manual" sort of the user, which should take precedence
        old_sort, old_order = prepare_table_before_inserting(table)

        table.setRowCount(len(transactions_tuples) + len(old_transactions))
        table.setColumnCount(len(TABLE_HEADERS))
        table.setHorizontalHeaderLabels(TABLE_HEADERS)

        i = 0

        for index, old_new_transaction in enumerate(transactions_tuples):
            old_transaction, new_transaction = old_new_transaction
            if old_transaction:
                hashes_identical = new_transaction.hash_value == old_transaction.hash_value
                values_to_render = [
                    (index + 1, index + 1),
                    (new_transaction.iban_othr, old_transaction.iban_othr),
                    (new_transaction.name, old_transaction.name),
                    (new_transaction.town_country, old_transaction.town_country),
                    (new_transaction.currency, old_transaction.currency),
                    (new_transaction.amount, old_transaction.amount),
                    (new_transaction.bank_identifier, old_transaction.bank_identifier),
                    (hashes_identical, True),
                    (IDENTICAL_TRANSACTION, IDENTICAL_TRANSACTION) if old_transaction == new_transaction else (MODIFIED_TRANSACTION, MODIFIED_TRANSACTION)
                ]
            else:
                values_to_render = [
                    (index + 1, None),
                    (new_transaction.iban_othr, None),
                    (new_transaction.name, None),
                    (new_transaction.town_country, None),
                    (new_transaction.currency, None),
                    (new_transaction.amount, None),
                    (new_transaction.bank_identifier, None),
                    ("", None),
                    (NEW_TRANSACTION, None)
                ]

            j = 0
            for new, old in values_to_render:
                if old is not None:
                    if old != new:
                        item = QtWidgets.QTableWidgetItem(f"{new} (was {old})")
                        if old is True:  # Do not write an "old" value
                            item = QtWidgets.QTableWidgetItem(str(new))
                        item.setBackground(QtGui.QColor(255, 117, 10))  # orange
                    else:
                        item = QtWidgets.QTableWidgetItem(str(new))
                else:
                    item = QtWidgets.QTableWidgetItem(str(new))
                    item.setBackground(QtGui.QColor(130, 180, 130))  # green
                table.setItem(i, j, item)
                j += 1
            i += 1

        # Now also put the old transactions that have no match in the table
        #logging.debug(old_transactions)
        for index, transaction in enumerate(old_transactions):
            values_to_render = [index + len(transactions_tuples) + 1, transaction.iban_othr, transaction.name, transaction.town_country,
                                transaction.currency, transaction.amount, transaction.bank_identifier,
                                "", OLD_TRANSACTION]
            j = 0
            for k in values_to_render:
                item = QtWidgets.QTableWidgetItem(str(k))
                item.setBackground(QtGui.QColor(255, 50, 50))  # red
                table.setItem(i, j, item)
                j += 1
            i += 1

        # restore order
        perform_followup_on_table_after_inserting(table, old_sort, old_order)

        table.resizeColumnsToContents()

    def pop_best_match(self, new_transaction: Transaction, old_transactions: list[Transaction]):
        good_match = None
        good_match_index = 0
        better_match = None
        better_math_index = 0
        for index, old_transaction in enumerate(old_transactions):
            if (new_transaction.iban_othr == old_transaction.iban_othr and
                    new_transaction.name == old_transaction.name and
                    new_transaction.bank_identifier == old_transaction.bank_identifier
            ):
                good_match = old_transaction
                good_match_index = index
                if(new_transaction.town_country == old_transaction.town_country and
                    new_transaction.amount == old_transaction.amount and
                    new_transaction.currency == old_transaction.currency
                ):
                    better_match = None
                    better_math_index = 0
                    if new_transaction.hash_value == old_transaction.hash_value:
                        # identical match
                        del old_transactions[index]
                        return old_transaction
        if better_match:
            del old_transactions[better_math_index]
            return better_match
        if good_match:
            del old_transactions[good_match_index]
        return good_match

    def parse_transactions(self, pain_file: PainContent):
        # logging.debug(etree.tostring(pain_file.xml_tree))
        transactions: list[Transaction] = []
        xml_tree = etree.parse(BytesIO(pain_file.pain_xml_content), self.parser)
        #for element in xml_tree.iter():
        #    logging.debug(f"{element.tag} - {element.text}")
        for transaction_info in xml_tree.iter(f"{pain_file.specification.namespace}CdtTrfTxInf"):
            logging.debug(transaction_info)

            # Find the PmtId element, which we
            for elem in transaction_info.findall(f"{pain_file.specification.namespace}PmtId"):
                # Remove the element
                transaction_info.remove(elem)

            logging.debug(f"Hashing {etree.tostring(transaction_info)}")
            hash_value = hashlib.blake2s(etree.tostring(transaction_info)).hexdigest().upper()

            # On Purpose we don't care about:
            # 03.ch.02: PmtTpInf, XchgRateInf, ChrgBr, ChqInstr, UltmtDbtr
            # for now, although unclear if this would be necessary to prevent fraudulent payments

            amount_tag = direct_single_child(transaction_info, f"{pain_file.specification.namespace}Amt")
            try:
                # We require exactly one InstdAmt ...
                inst_amount = direct_single_child(amount_tag, f"{pain_file.specification.namespace}InstdAmt")
                currency = inst_amount.get(f"Ccy")
                amount = inst_amount.text
            except NotExactlyOneElementException:
                # ... or Exactly one EqvtAmt
                equivalent_amount = direct_single_child(amount_tag, f"{pain_file.specification.namespace}EqvtAmt")
                equivalent_currency = direct_single_child(equivalent_amount,
                                                                  f"{pain_file.specification.namespace}CcyOfTrf").text
                amount_tag = direct_single_child(equivalent_amount, f"{pain_file.specification.namespace}Amt")
                currency = amount_tag.get(f"Ccy") + f"(equivalent in {equivalent_currency})"
                amount = amount_tag.text

            try:
                amount += " " + direct_single_child(transaction_info, f"{pain_file.specification.namespace}ChrgBr").text
            except NotExactlyOneElementException:
                pass

            # Bank is completely optional...
            # But the old Swiss standard is a little stupid, e.g. BIC (Swiss) versus BICFI (everyone else)
            if pain_file.specification.namespace == NAMESPACE_03_CH_02:
                bank_identifier = self.parse_bank_03_ch_02(pain_file, transaction_info)
            else:  # pain_file.namespace == NAMESPACE_09:
                bank_identifier = self.parse_bank_09(pain_file, transaction_info)

            # We require a creditor
            cdtr = direct_single_child(transaction_info, f"{pain_file.specification.namespace}Cdtr")
            # No name, no address and no town/country is fine
            name = direct_multi_child_text(cdtr, f"{pain_file.specification.namespace}Nm")
            try:
                postal_address = direct_single_child(cdtr, f"{pain_file.specification.namespace}PstlAdr")
                town = direct_multi_child_text(postal_address, f"{pain_file.specification.namespace}TwnNm")
                ctry = direct_multi_child_text(postal_address, f"{pain_file.specification.namespace}Ctry")
                town_country_list = [x for x in (town, ctry) if x]
                town_country = " / ".join(town_country_list)
            except NotExactlyOneElementException:
                town_country = ""

            # We require no or exactly one CdtrAcct or ChrgsAcct
            account = None
            iban_othr = ""
            try:
                account = direct_single_child(transaction_info, f"{pain_file.specification.namespace}CdtrAcct")
            except NotExactlyOneElementException:
                try:
                    account = direct_single_child(transaction_info, f"{pain_file.specification.namespace}ChrgsAcct")
                except NotExactlyOneElementException:
                    iban_othr = ""

            if account is not None:
                # With exactly one ID
                acc_id = direct_single_child(account, f"{pain_file.specification.namespace}Id")
                try:
                    iban_othr = direct_single_child(acc_id, f"{pain_file.specification.namespace}IBAN").text
                except NotExactlyOneElementException:
                    othr = direct_single_child(acc_id, f"{pain_file.specification.namespace}Othr")
                    iban_othr = direct_single_child(othr, f"{pain_file.specification.namespace}Id").text

            transactions.append(Transaction(currency, amount, bank_identifier, name, town_country, iban_othr, hash_value, etree.tostring(transaction_info, pretty_print=True).decode()))
        transactions.sort(key=lambda x: (x.name, x.iban_othr, x.bank_identifier, x.town_country, x.currency, x.amount, x.hash_value))
        pain_file.transactions = transactions

    def parse_bank_03_ch_02(self, pain_file: PainContent, transaction_info: Element):
        bic = "BIC"
        identifiers = self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "IntrmyAgt1")
        identifiers.extend(self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "CdtrAgt"))
        return " / ".join(identifiers)

    def parse_bank_09(self, pain_file: PainContent, transaction_info: Element):
        bic = "BICFI"
        identifiers = self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "IntrmyAgt1")
        identifiers.extend(self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "IntrmyAgt2"))
        identifiers.extend(self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "IntrmyAgt3"))
        identifiers.extend(self.parse_common_bank_identifiers(pain_file, transaction_info, bic, "CdtrAgt"))
        return " / ".join(identifiers)

    def parse_common_bank_identifiers(self, pain_file: PainContent, transaction_info: Element, bic_name: str,
                                      element_name: str) -> list[str]:
        # BICFI
        identifiers = []
        try:
            agent = direct_single_child(transaction_info, f"{pain_file.specification.namespace}{element_name}")
            fin_inst = direct_single_child(agent, f"{pain_file.specification.namespace}FinInstnId")
        except NotExactlyOneElementException:
            return []
        try:
            identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}{bic_name}").text)
        except NotExactlyOneElementException:
            pass
        try:
            clearing_system_member_id = direct_single_child(fin_inst, f"{pain_file.specification.namespace}ClrSysMmbId")

            member_id = direct_single_child(clearing_system_member_id, f"{pain_file.specification.namespace}MmbId").text
            identifiers.append(member_id)
            clearing_system_id = direct_single_child(clearing_system_member_id,
                                                             f"{pain_file.specification.namespace}ClrSysId")
            prtry = direct_single_child(clearing_system_id, f"{pain_file.specification.namespace}Prtry").text
            identifiers.append(prtry)
            clearing_system_id_code = direct_single_child(clearing_system_id, f"{pain_file.specification.namespace}Cd").text
            identifiers.append(clearing_system_id_code)
        except NotExactlyOneElementException:
            pass
        try:
            identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}Nm").text)
        except NotExactlyOneElementException:
            pass
        postal_address = None
        try:
            postal_address = direct_single_child(fin_inst, f"{pain_file.specification.namespace}PstlAdr")
        except NotExactlyOneElementException:
            pass
        if postal_address:
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}AdrTp"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}Dept"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}SubDept"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}StrtNm"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}BldgNb"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}PstCd"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}TwnNm"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}CtrySubDvsn"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}Ctry"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}AdrLine"))
            except NotExactlyOneElementException:
                pass
        generic_othr = False
        try:
            generic_othr = direct_single_child(fin_inst, f"{pain_file.specification.namespace}Othr")
        except NotExactlyOneElementException:
            pass
        if generic_othr:
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}Id"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}SchmeNm"))
            except NotExactlyOneElementException:
                pass
            try:
                identifiers.append(direct_single_child(fin_inst, f"{pain_file.specification.namespace}Issr"))
            except NotExactlyOneElementException:
                pass
        if bic_name == "BICFI":
            try:
                identifiers.append(direct_single_child(transaction_info, f"{pain_file.specification.namespace}LEI").text)
            except NotExactlyOneElementException:
                pass
        return identifiers

    def clear_and_forget_history(self):
        self.clear_and_forget()
        self.settings.setValue("last_file", "")

    def clear_and_forget(self):
        self.clear_table()
        self.last_file = None
        self.loaded_transaction_tuples = []

    def clear_table(self):
        self.label_differences.setText("")
        table = self.tw_payments_table
        table.clearContents()
        table.setRowCount(0)
        self.statusBar().showMessage("")

    @staticmethod
    def _popup_info_message(title: str, text: str):
        logging.info(text)
        msg_box = QtWidgets.QMessageBox()
        horizontal_spacer = QtWidgets.QSpacerItem(700, 0, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        msg_box.setIcon(QtWidgets.QMessageBox.Icon.Warning)
        msg_box.setWindowTitle(title)
        msg_box.setText(text)
        layout = msg_box.layout()
        # noinspection PyArgumentList
        # noinspection PyUnresolvedReferences
        layout.addItem(horizontal_spacer, layout.rowCount(), 0, 1, layout.columnCount())
        #msg_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg_box.exec()

    @staticmethod
    def exit_app():
        sys.exit()

    @staticmethod
    def about():
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Icon.Information)
        msg.setWindowTitle("About")
        msg.setText("This is Riskless Pain. Copyright Pentagrid AG.")
        msg.exec()


def run_tests(main_window: MainWindow=None):
    logging.debug("Wait for GUI to start")
    time.sleep(2)
    run_tests_internet_files(main_window)
    time.sleep(2)
    #run_tests_09(main_window)
    time.sleep(2)
    #run_tests_03_ch_02(main_window)

def run_tests_internet_files(main_window: MainWindow = None):
    sleep = 1
    base = os.path.join(os.path.dirname(__file__), "test-files-internet")
    for root, dirs, files in os.walk(base):
        for file in files:
            full_path = os.path.join(root, file)
            logging.debug(full_path)
            main_window.load_file_test_signal.emit([full_path])
            time.sleep(sleep)
            main_window.clear_test_signal.emit()
            main_window.load_file_test_signal.emit([full_path])
            time.sleep(sleep)

def run_tests_09(main_window: MainWindow = None):
    sleep = 1
    base = os.path.join(os.path.dirname(__file__), "test-files", "pain.001.001.09_base.xml")
    base_following_month = os.path.join(os.path.dirname(__file__),
                                        "test-files", "pain.001.001.09_base_following_month.xml")
    colab_system_http = os.path.join(os.path.dirname(__file__), "test-files", "pain.001.001.09_colab_system_http.xml")
    colab_doctype = os.path.join(os.path.dirname(__file__), "test-files", "pain.001.001.09_colab_doctype.xml")
    colab_document_entity = os.path.join(os.path.dirname(__file__),
                                         "test-files", "pain.001.001.09_colab_document_entity.xml")
    document_entity_passwd = os.path.join(os.path.dirname(__file__),
                                         "test-files", "pain.001.001.09_document_entity_passwd.xml")
    xinclude = os.path.join(os.path.dirname(__file__),
                                          "test-files", "pain.001.001.09_xinclude.xml")
    main_window.load_file_test_signal.emit([base])
    time.sleep(sleep)
    main_window.load_file_test_signal.emit([base_following_month])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([base, base_following_month])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([colab_system_http])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([colab_doctype])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([colab_document_entity])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([document_entity_passwd])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([xinclude])
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([base, base_following_month])

def run_tests_03_ch_02(main_window: MainWindow = None):
    sleep = 1
    base = os.path.join(os.path.dirname(__file__), "test-files", "pain.001.001.03.ch.02_base.xml")
    base_following_month = os.path.join(os.path.dirname(__file__),
                                        "test-files", "pain.001.001.03.ch.02_base_following_month.xml")
    colab_system_http = os.path.join(os.path.dirname(__file__), "test-files", "pain.001.001.03.ch.02_colab_system_http.xml")
    main_window.load_file_test_signal.emit([base])
    time.sleep(sleep)
    main_window.load_file_test_signal.emit([base_following_month])
    time.sleep(sleep)
    main_window.clear_test_signal.emit()
    main_window.load_file_test_signal.emit([base, base_following_month])
    time.sleep(sleep)
    main_window.load_file_test_signal.emit([colab_system_http])
    time.sleep(sleep)
    main_window.load_file_test_signal.emit([base, base_following_month])

def main_gui():
    app = QtWidgets.QApplication(sys.argv)
    svg = os.path.join(os.path.dirname(sys.modules[__name__].__file__), 'ui', 'risklesspain.svg')
    print(svg)
    app.setWindowIcon(QtGui.QIcon(svg))
    main_window = MainWindow()
    main_window.show()

    if "--test" in " ".join(sys.argv):
        t = threading.Thread(target=run_tests, kwargs={"main_window": main_window})
        t.start()
    app.exec()

if __name__ == "__main__":
    main_gui()