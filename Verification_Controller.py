#from msili.schema import Error
import sys
from PyQt5 import QtCore, QtGui, QtWidgets

import Start
import ECDSA
import ECDH
import AES128
import Verification_code
import Verificado
import N_Verificado

class Controller:
    def __init__(self):
        self.Start_Window = QtWidgets.QDialog()
        self.Start_ui = Start.Ui_Dialog()
        self.Start_ui.setupUi(self.Start_Window)
        
        self.ECDSA_Window = QtWidgets.QDialog()
        self.ECDSA_ui = ECDSA.Ui_Dialog()
        self.ECDSA_ui.setupUi(self.ECDSA_Window)
        
        self.ECDH_Window = QtWidgets.QDialog()
        self.ECDH_ui = ECDH.Ui_Dialog()
        self.ECDH_ui.setupUi(self.ECDH_Window)
        
        self.AES128_Window = QtWidgets.QDialog()
        self.AES128_ui = AES128.Ui_Dialog()
        self.AES128_ui.setupUi(self.AES128_Window)
        
        self.Verificado_Window = QtWidgets.QDialog()
        self.Verificado_ui = Verificado.Ui_Dialog()
        self.Verificado_ui.setupUi(self.Verificado_Window)
        
        self.N_Verificado_Window = QtWidgets.QDialog()
        self.N_Verificado_ui= N_Verificado.Ui_Dialog()
        self.N_Verificado_ui.setupUi(self.N_Verificado_Window)
        
        self.Start_ui.pushButton.clicked.connect(self.clicked_ECDSA)
        self.Start_ui.pushButton_2.clicked.connect(self.clicked_ECDH)
        self.Start_ui.pushButton_3.clicked.connect(self.clicked_AES128)
        
        self.ECDSA_ui.pushButton.clicked.connect(self.clicked_verify)
        self.ECDSA_ui.pushButton_2.clicked.connect(self.clicked_generate)
        self.ECDSA_ui.pushButton_3.clicked.connect(self.clicked_back_ecdsa)
        
        self.ECDH_ui.pushButton.clicked.connect(self.clicked_ecdh)
        self.ECDH_ui.pushButton_2.clicked.connect(self.clicked_generate)
        self.ECDH_ui.pushButton_4.clicked.connect(self.clicked_compare)
        self.ECDH_ui.pushButton_3.clicked.connect(self.clicked_back_ecdh)
        
        self.AES128_ui.pushButton.clicked.connect(self.clicked_encrypt)
        self.AES128_ui.pushButton_2.clicked.connect(self.clicked_decrypt)
        self.AES128_ui.pushButton_3.clicked.connect(self.clicked_back_aes128)
        
        self.ECDSA_ui.plainTextEdit_1
        self.ECDSA_ui.plainTextEdit_2
        self.ECDSA_ui.plainTextEdit_3
        self.ECDSA_ui.plainTextEdit_4
        self.ECDSA_ui.plainTextEdit_5
        self.ECDSA_ui.plainTextEdit_6
        self.ECDSA_ui.plainTextEdit_7
        self.ECDSA_ui.plainTextEdit_8
        
        self.ECDH_ui.plainTextEdit_1
        self.ECDH_ui.plainTextEdit_2
        self.ECDH_ui.plainTextEdit_3
        self.ECDH_ui.plainTextEdit_4
        self.ECDH_ui.plainTextEdit_5
        self.ECDH_ui.plainTextEdit_6
        
        self.AES128_ui.plainTextEdit_1
        self.AES128_ui.plainTextEdit_2
        self.AES128_ui.plainTextEdit_3
        self.AES128_ui.plainTextEdit_4
        self.AES128_ui.plainTextEdit_5
        self.AES128_ui.plainTextEdit_6
        
        self.pri = None
            
    def clicked_back_ecdsa(self):
        self.Start_Window.show()
        self.ECDSA_Window.close()
        
    def clicked_back_ecdh(self):
        self.Start_Window.show()
        self.ECDH_Window.close()
        
    def clicked_back_aes128(self):
        self.Start_Window.show()
        self.AES128_Window.close()
        
    def clicked_ECDSA(self):
        self.Start_Window.close()
        self.ECDSA_Window.show()
    
    def clicked_ECDH(self):
        self.Start_Window.close()
        self.ECDH_Window.show()
        
    def clicked_AES128(self):
        self.Start_Window.close()
        self.AES128_Window.show()
        
    def clicked_verify(self):
        msg = self.ECDSA_ui.plainTextEdit_5.toPlainText()
        sig = self.ECDSA_ui.plainTextEdit_7.toPlainText()
        pub = self.ECDSA_ui.plainTextEdit_6.toPlainText()
        
        self.show_popup(Verification_code.verification(pub, sig, msg))

    def clicked_generate(self):
        msg = self.ECDSA_ui.plainTextEdit_3.toPlainText()

        self.pri, pub, sig = Verification_code.generation(msg)
        has = Verification_code.hash_calculation(msg)
        
        if self.ECDSA_Window.isActiveWindow():
            self.ECDSA_ui.plainTextEdit_4.setPlainText(has)
            self.ECDSA_ui.plainTextEdit_8.setPlainText(self.pri)
            self.ECDSA_ui.plainTextEdit_1.setPlainText(pub)
            self.ECDSA_ui.plainTextEdit_2.setPlainText(sig)
        
        if self.ECDH_Window.isActiveWindow():
            self.ECDH_ui.plainTextEdit_1.setPlainText(pub)
        
    def clicked_ecdh(self):
        remote_pub = self.ECDH_ui.plainTextEdit_2.toPlainText()
        if self.pri:
            sec = Verification_code.ecdh(self.pri, remote_pub)
            self.ECDH_ui.plainTextEdit_3.setPlainText(sec)
            self.ECDH_ui.plainTextEdit_4.setPlainText(sec[:32])
        else:
            pass
    
    def clicked_compare(self):
        dh1 = self.ECDH_ui.plainTextEdit_5.toPlainText().upper()
        dh2 = self.ECDH_ui.plainTextEdit_6.toPlainText().upper()
        self.show_popup(dh1==dh2)
            
        
    def clicked_encrypt(self):
        msg = self.AES128_ui.plainTextEdit_1.toPlainText()
        key = self.AES128_ui.plainTextEdit_2.toPlainText()
        
        key, text = Verification_code.encrypt_aes128(msg, key)
        if self.AES128_ui.plainTextEdit_2.toPlainText()=='':
            self.AES128_ui.plainTextEdit_2.setPlainText(key)
        self.AES128_ui.plainTextEdit_3.setPlainText(text)
        
    def clicked_decrypt(self):
        msg = self.AES128_ui.plainTextEdit_6.toPlainText()
        key = self.AES128_ui.plainTextEdit_4.toPlainText()
        
        text = Verification_code.decrypt_aes128(msg, key)
        self.AES128_ui.plainTextEdit_5.setPlainText(text)
        
    def show_window(self):
            self.Start_Window.show()
        
    def show_popup(self, flag):
        if flag:
            self.Verificado_Window.show()
            self.N_Verificado_Window.close()
        else:
            self.Verificado_Window.close()
            self.N_Verificado_Window.show()
            

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)    
    controller = Controller()    
    controller.show_window()
    sys.exit(app.exec_())