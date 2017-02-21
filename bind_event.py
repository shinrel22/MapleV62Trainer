from kivy.uix.gridlayout import GridLayout
from kivy.uix.checkbox import CheckBox
from kivy.app import App


class DemoBox(GridLayout):

    def __init__(self, **kwargs):
        super(DemoBox, self).__init__(**kwargs)
        self.cols = 2

        # text="Normal binding to event"
        btn = CheckBox()
        btn.fbind('on_press', self.on_event)

        # text="Normal binding to a property change"
        btn2 = CheckBox()
        btn2.fbind('state', self.on_property, dcm="DCM")

        # text="A: Using function with args."
        btn3 = CheckBox()
        btn3.fbind('on_press', self.on_event_with_args, 'right',
                       tree='birch', food='apple')

        # text="Unbind A."
        btn4 = CheckBox()
        btn4.fbind('on_press', self.unbind_a, btn3)

        # text="Use a flexible function"
        btn5 = CheckBox()
        btn5.fbind('on_press', self.on_anything)

        # text = "B: Using flexible functions with args. For hardcores."
        btn6 = CheckBox()
        btn6.fbind('on_press', self.on_anything, "1", "2", monthy="python", dcm="aa")

        # text="Force dispatch B with different params"
        btn7 = CheckBox()
        btn7.fbind('on_press', btn6.dispatch, 'on_press', 6, 7, monthy="other python")

        for but in [btn, btn2, btn3, btn4, btn5, btn6, btn7]:
            self.add_widget(but)

    def on_event(self, obj):
        print("Typical event from", obj)

    def on_event_with_args(self, side, obj, tree=None, food=None):
        print("Event with args", obj, side, tree, food)

    def on_property(self, obj, value, dcm):
        if value == "down":
            print("Typical property change from", obj, "to", value, dcm)
        else:
            print("di me may")

    def on_anything(self, *args, **kwargs):
        print('The flexible function has *args of', str(args),
            "and **kwargs of", str(kwargs))
        return True

    def unbind_a(self, btn, event):
        btn.funbind('on_press', self.on_event_with_args, 'right',
                        tree='birch', food='apple')


class DCM(App):
    def build(self):
        return DemoBox()


if __name__ == "__main__":
    DCM().run()