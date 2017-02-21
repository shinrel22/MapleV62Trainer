from kivy.app import App
from kivy.uix.screenmanager import Screen


class LoginScreen(Screen):
    pass


class MainApp(App):
    def build(self):
        return LoginScreen()


if __name__ == "__main__":
    MainApp().run()