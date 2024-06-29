
import socket
import dearpygui.dearpygui as dpg
import Encryptor

class NetworkManager:
    # class for working with sockets
    def __init__(self, host='localhost', port=9090):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((host, port))
        except (ValueError, ConnectionRefusedError) as err:
            print(err)

class App:
    def __init__(self):
        self.encrypt = Encryptor
        self.user_id = None
        self.network_manager = NetworkManager()
        # main client window
        dpg.create_context()
        dpg.create_viewport(title="Queneazi", width=1000, height=600, resizable=False,
                            small_icon="customer_user_icon_261455.ico", x_pos=1920 // 2 - 575)
        # binds the font
        with dpg.font_registry():
            default_font = dpg.add_font(file="fonts/MinecraftRegular-Bmg3.otf", size=20)
            custom_font = dpg.add_font(file="fonts/MinecraftRegular-Bmg3.otf", size=50)

        # creates a selection window inside the client
        with dpg.window(no_collapse=True, no_close=True, no_resize=True, no_title_bar=True,
                        tag="main_menu") as main_menu_login:
            # Application Name
            with dpg.group(horizontal=True):
                title = dpg.add_text(
                    default_value="SERVER MANAGER",
                    pos=[1000 // 2 - 200, 600 // 2 - 100]
                )
                dpg.bind_item_font(title, custom_font)
            # group of login and registration buttons
            with dpg.group(horizontal=True, pos=[1000 // 2 - 100, 600 // 2 + 40]):
                dpg.add_button(label="SIGN IN", callback=lambda: self.switch_window("auth_menu"))
                dpg.add_button(label="SIGN UP", callback=lambda: self.switch_window("register_menu"))

        # login menu
        with dpg.window(no_close=True, no_resize=True, no_title_bar=True, show=False,
                        tag="auth_menu") as auth_menu:
            dpg.add_text("Your login:")
            dpg.add_input_text(tag="login_enter_auth", width=600 - 30)

            dpg.add_text("Your password:")
            dpg.add_input_text(password=True, tag="password_enter_auth", width=600 - 30)

            dpg.add_button(label="Enter", width=100, callback=self.set_login_password_auth)
            dpg.add_separator()
            dpg.add_spacer(width=35)
            dpg.add_button(label="Back", callback=lambda: self.switch_window("main_menu"))

        # registration menu
        with dpg.window(no_close=True, no_resize=True, no_title_bar=True, show=False,
                        tag="register_menu") as register_menu:
            dpg.add_text("Login:")
            dpg.add_input_text(tag="login_enter_register", width=600 - 30)

            dpg.add_text("Password:")
            dpg.add_input_text(password=True, tag="password_enter_register1", width=600 - 30)
            dpg.add_text("Re-enter password:")
            dpg.add_input_text(password=True, tag="password_enter_register2", width=600 - 30)

            dpg.add_button(label="Enter", width=100, callback=self.set_log_pass_reg)
            dpg.add_separator()
            dpg.add_spacer(width=35)
            dpg.add_button(label="Back", callback=lambda: self.switch_window("main_menu"))

        # the most important window for working with the server
        with dpg.window(no_close=True, no_resize=True, no_title_bar=True, show=False,
                        tag="main_window") as main_window:
            dpg.add_input_text(tag="transfer_panel", multiline=True, width=1000, height=300, readonly=True)
            dpg.add_separator()
            dpg.add_spacer(height=10)
            dpg.add_input_text(tag="submit_path", width=600 - 30)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Submit", width=150, callback=self.set_value_transfer_panel)
                dpg.add_button(label="Exit", width=150)

        dpg.bind_font(default_font)
        dpg.set_primary_window(window=main_menu_login, value=True)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

    # change windows
    @staticmethod
    def switch_window(target_window):
        dpg.configure_item("main_menu", show=False)
        dpg.configure_item("auth_menu", show=False)
        dpg.configure_item("register_menu", show=False)
        dpg.configure_item("main_window", show=False)
        dpg.configure_item(target_window, show=True)
        dpg.set_primary_window(window=target_window, value=True)

    # login function
    def set_login_password_auth(self):
        login = dpg.get_value("login_enter_auth")
        password = dpg.get_value("password_enter_auth")
        passlog = self.encrypt.encrypt_AES_CBC('papa', f'@{login} {password}')
        self.network_manager.sock.send(passlog.encode('utf-8'))
        data = self.network_manager.sock.recv(1024).decode('utf-8')
        data = self.encrypt.decrypt_AES_CBC('papa', data)
        if data[1:] == 'Successful logged':
            self.user_id = data[0]
            self.switch_window("main_window")

    # registration function
    def set_log_pass_reg(self):
        login = dpg.get_value("login_enter_register")
        password1 = dpg.get_value("password_enter_register1")
        password2 = dpg.get_value("password_enter_register2")
        if password1 == password2:
            passlog = self.encrypt.encrypt_AES_CBC('papa', f'#{login} {password2}')
            self.network_manager.sock.send(passlog.encode('utf-8'))
            data = self.network_manager.sock.recv(1024).decode('utf-8')
            data = self.encrypt.decrypt_AES_CBC('papa', data)
            if data[1:] == 'Successful registered':
                self.user_id = data[0]
                self.switch_window("main_window")
            else:
                pass
        else:
            print("Error: Passwords don't match")

    # main function that changes values in the main window
    def set_value_transfer_panel(self):
        submit_path = self.encrypt.encrypt_AES_CBC("papa", f'{self.user_id}{dpg.get_value("submit_path")}')
        self.network_manager.sock.send(submit_path.encode('utf-8'))
        data = self.network_manager.sock.recv(1024).decode('utf-8')
        dpg.set_value("transfer_panel", self.encrypt.decrypt_AES_CBC('papa', data))
        dpg.set_value("submit_path", "")


if __name__ == "__main__":
    app = App()
