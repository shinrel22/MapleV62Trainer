from kivy.app import App
from kivy.uix.screenmanager import ScreenManager
from kivy.lang.builder import Builder

from MapleTrainer.loginScreen import LoginScreen
from MapleTrainer.toolScreen import ToolScreen


Builder.load_file("trainer.kv")

class ToolScr(ToolScreen):
    pass


class LoginScr(LoginScreen):
    pass


class ScreenMng(ScreenManager):
    pass


class MapleTrainer(App):
    def build(self):
        return ScreenMng()


if __name__ == "__main__":
    MapleTrainer().run()
