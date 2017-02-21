from kivy.app import App
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.gridlayout import GridLayout
from kivy.uix.checkbox import CheckBox
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.properties import StringProperty
from kivy.clock import Clock

from MapleTrainer.procListView import ListRV
from MapleTrainer.hacking_features import HackFeatures


HACK = HackFeatures()
CHECKBOXTOOLS = {
    "Maximum Movement Speed"    : HACK.movSpeed,
    "Maximum Physical Defense"  : HACK.defHack,
    "No Knock Back"             : HACK.noKnockBack,
    "Maximum Accuracy"          : HACK.accHack,
    "Air Swim"                  : HACK.airSwim,
    "Maximum Mana Regeneration" : HACK.manaRegen,
    "Maximum Attack Speed"      : HACK.speedAtt,
    "Unlimited Attack"          : HACK.unlimitedAtt,
    "Full God Mode"             : HACK.fullGodmode,
    "Full Map Attack"           : HACK.fullMapAttack,
    "CC VAC"                    : HACK.ccVac
}


class ToolScreen(Screen):
    pass


class CurrentProcessBox(BoxLayout):
    procName = StringProperty(None)
    pid = StringProperty(None)
    def __init__(self, **kwargs):
        super().__init__()
        Clock.schedule_interval(self.update, 1)

    def update(self, dt):
        self.procName = HACK.procName
        self.pid = str(HACK.pid)



class HackScreen(Screen):
    pass


class AutoScreen(Screen):
    pass


class AccountInfoScreen(Screen):
    pass

class ToolScreenManager(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__()

        self.vacPop = MobVacPopup()
        self.dmgPop = DamageControllerPopup()


class HackGrid(GridLayout):
    def __init__(self, **kwargs):
        super().__init__()
        for tool in CHECKBOXTOOLS:
            label = Label(text=tool, halign="left",valign="middle", text_size=(200, 20))
            checkbox = CheckBox(color=(0,100,50,1))
            checkbox.fbind("state", self.checkbox_operation, hackFunc=CHECKBOXTOOLS[tool])
            self.add_widget(label)
            self.add_widget(checkbox)

    def checkbox_operation(self, obj, value, hackFunc):
        if value == "down":
            hackFunc(active=True)

        else:
            hackFunc(active=False)


class ProcPopup(Popup):
    def __init__(self, **kwargs):
        super().__init__()
        self.title = "Process List"
        self.title_align = "center"

        procBox = BoxLayout(orientation="vertical")
        self.add_widget(procBox)

        self.proListReview = ListRV()
        button = Button(text="Select", size_hint=(1, 0.1))
        button.fbind("on_press", self.selectProc_operation)

        allProc = HACK.dbg.enumerate_processes()
        for proc in allProc:
            self.proListReview.data.append({"text": "%s PID:%s" %(allProc[proc].decode("utf-8"), str(proc))})

        procBox.add_widget(self.proListReview)
        procBox.add_widget(button)

    def selectProc_operation(self, obj):
        if self.proListReview.selectedItem:
            procName, pid = self.proListReview.selectedItem["text"].split(" ")
            pid = int(pid[4:])
            HACK.h_process = HACK.dbg.open_process(pid=pid)
            HACK.procName = procName
            HACK.pid = pid
        self.dismiss()


class SelectProcessButton(Button):
    def on_press(self):
        ProcPopup().open()


class MobVacPopup(Popup):
    def __init__(self, **kwargs):
        super().__init__()

        box = BoxLayout(orientation="vertical")
        self.add_widget(box)

        grid = GridLayout(cols=3)
        box.add_widget(grid)
        modeList = ["Left", "Right", "Off"]
        for mode in modeList:
            grid.add_widget(Label(text=mode))

        for mode in modeList:
            checkbox = CheckBox(group="1", color=(0,100,50,1))
            checkbox.fbind("state", self.mobVac_operation, active=mode.lower())
            grid.add_widget(checkbox)

        closeButton = Button(text="Close", on_release=self.dismiss, size_hint=(1, 0.4))
        box.add_widget(closeButton)

    def mobVac_operation(self, obj, value, active):
        if value == "down":
            HACK.mobsVAC(active=active)
        else:
            HACK.mobsVAC(active="off")

class DamageControllerPopup(Popup):
    def __init__(self, **kwargs):
        super().__init__()
        box = BoxLayout(orientation="vertical")
        self.add_widget(box)

        subBox = BoxLayout(orientation="vertical")
        box.add_widget(subBox)

        grid = GridLayout(cols=3)
        subBox.add_widget(grid)

        grid.add_widget(Label(text="Max Damage"))
        maxInc = IncreaseDmgButton(text="Increase")
        maxInc.fbind("on_press", self.damage_operation, active="maxi")
        maxDec = DecreaseDmgButton(text="Decrease")
        maxDec.fbind("on_press", self.damage_operation, active="maxd")
        grid.add_widget(maxInc)
        grid.add_widget(maxDec)

        grid.add_widget(Label(text="Min Damage"))
        minInc = IncreaseDmgButton(text="Increase")
        minInc.fbind("on_press", self.damage_operation, active="mini")

        minDec = DecreaseDmgButton(text="Decrease")
        minDec.fbind("on_press", self.damage_operation, active="mind")
        grid.add_widget(minInc)
        grid.add_widget(minDec)

        resetButton = Button(text="Reset", size_hint=(1, 0.5))
        resetButton.fbind("on_press", self.damage_operation, active="reset")
        subBox.add_widget(resetButton)

        box.add_widget(Button(text="Close", size_hint=(1, 0.3), on_press=self.dismiss))

    def damage_operation(self, obj, active):
        HACK.dmgHack(active=active)


class IncreaseDmgButton(Button):
    pass


class DecreaseDmgButton(Button):
    pass


class Main(App):
    def build(self):
        return ToolScreen()

if __name__ == "__main__":
    Main().run()