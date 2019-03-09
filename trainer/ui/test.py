from kivy.app import App
from kivy.properties import ObjectProperty
from kivy.uix.button import Button


class MyButton(Button):
    def __init__(self, **kwargs):
        super().__init__()


class Main(App):
    def build(self):
        return MyButton()


if __name__ == "__main__":
    Main().run()