from kivy.app import App
from kivy.uix.screenmanager import Screen


class LoginScreen(Screen):
    def login(self):
        self.manager.current = "tool"


class MainApp(App):
    def build(self):
        return LoginScreen()


if __name__ == "__main__":
    MainApp().run()