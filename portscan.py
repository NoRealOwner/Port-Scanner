import socket
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar
from PyQt5.QtCore import Qt, QThread, pyqtSignal

class PortScanThread(QThread):
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(str)

    def __init__(self, target_ip, start_port, end_port):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port

    def run(self):
        for port in range(self.start_port, self.end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    self.result_signal.emit(f"Port {port} is open. Used protocol: {service}\n")
                except socket.error:
                    self.result_signal.emit(f"Port {port} is open, but the used protocol couldn't be determined.\n")
            sock.close()
            self.progress_signal.emit(int((port - self.start_port + 1) / (self.end_port - self.start_port + 1) * 100))

        self.finished_signal.emit("Scan completed.")

class PortScanApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Port Scan Tool')

        self.target_ip_label = QLabel('Target IP:')
        self.target_ip_input = QLineEdit()
        self.start_port_label = QLabel('Start Port:')
        self.start_port_input = QLineEdit()
        self.end_port_label = QLabel('End Port:')
        self.end_port_input = QLineEdit()

        self.progress_bar = QProgressBar()
        self.scan_result = QTextEdit()
        self.scan_result.setReadOnly(True)

        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.scan_ports)

        layout = QVBoxLayout()
        layout.addWidget(self.target_ip_label)
        layout.addWidget(self.target_ip_input)
        layout.addWidget(self.start_port_label)
        layout.addWidget(self.start_port_input)
        layout.addWidget(self.end_port_label)
        layout.addWidget(self.end_port_input)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.scan_result)

        self.setLayout(layout)

    def scan_ports(self):
        # Disable the Scan button
        self.scan_button.setEnabled(False)

        target_ip = self.target_ip_input.text()
        start_port = int(self.start_port_input.text())
        end_port = int(self.end_port_input.text())

        # Reset progress bar at the beginning
        self.progress_bar.setValue(0)

        # Clear previous results
        self.scan_result.clear()

        self.thread = PortScanThread(target_ip, start_port, end_port)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.result_signal.connect(self.update_result)
        self.thread.finished_signal.connect(self.show_finished_message)
        self.thread.start()

    def update_progress(self, progress):
        self.progress_bar.setValue(progress)

    def update_result(self, result):
        self.scan_result.append(result)

    def show_finished_message(self, message):
        self.scan_result.append(message)

        # Enable the Scan button again
        self.scan_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    port_scan_app = PortScanApp()
    port_scan_app.show()
    sys.exit(app.exec_())
