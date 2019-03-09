from kivy.app import App
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.gridlayout import GridLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.checkbox import CheckBox
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.properties import StringProperty, BooleanProperty
from kivy.clock import Clock

from MapleTrainer.procListView import ListRV
from MapleTrainer.hacking_features import HackFeatures


HACK = HackFeatures()
CHECKBOXTOOLS = {
    "Maximum Movement Speed"    : [HACK.movSpeed, False],
    "Maximum Physical Defense"  : [HACK.defHack, False],
    "No Knock Back"             : [HACK.noKnockBack, False],
    "Maximum Accuracy"          : [HACK.accHack, False],
    "Air Swim"                  : [HACK.airSwim, False],
    "Maximum Mana Regeneration" : [HACK.manaRegen, False],
    "Maximum Attack Speed"      : [HACK.speedAtt, False],
    "Unlimited Attack"          : [HACK.unlimitedAtt, False],
    "Full God Mode"             : [HACK.fullGodmode, False],
    "Full Map Attack"           : [HACK.fullMapAttack, False],
    "CC VAC"                    : [HACK.ccVac, False]
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


class GameStatisticsScreen(Screen):
    damageCap = StringProperty(None)
    magicAttCap = StringProperty(None)
    mesoDropCap = StringProperty(None)
    mapID = StringProperty(None)
    playerCount = StringProperty(None)
    monsterCount = StringProperty(None)
    updateStatistic_switcher = BooleanProperty(False)

    def update_statistics(self, dt):
        statistics = HACK.statis()
        if not statistics:
            return None
        self.damageCap = statistics["damageCap"]
        self.magicAttCap = statistics["magicAttCap"]
        self.mesoDropCap = statistics["mesoDropCap"]
        self.mapID = statistics["mapID"]
        self.playerCount = statistics["playerCount"]
        self.monsterCount = statistics["monsterCount"]



    def on_enter(self, *args):
        if not self.updateStatistic_switcher:
            Clock.schedule_interval(self.update_statistics, 1)
            self.updateStatistic_switcher = True


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
            checkbox.fbind("state", self.checkbox_operation, hackFunc=CHECKBOXTOOLS[tool], funcName=tool)
            self.add_widget(label)
            self.add_widget(checkbox)

    def checkbox_operation(self, obj, value, hackFunc, funcName):
        if value == "down":
            hackFunc[0](active=True)
            CHECKBOXTOOLS[funcName][1] = True
        else:
            hackFunc[0](active=False)
            CHECKBOXTOOLS[funcName][1] = False


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


class SafeModeFAQPopup(Popup):
    pass


class SafeModeFAQLayout(FloatLayout):
    def __init__(self, **kwargs):
        super().__init__()
        self.safeModePopup = SafeModeFAQPopup()


class SafeModeBox(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__()
        self.safeMode = None

        self.size_hint = (1, 0.2)
        self.orientation = "horizontal"

        self.add_widget(Label(text="Safe Mode",text_size=(200, 17), halign="left"))
        checkbox = CheckBox(color=(0,100,50,1))
        checkbox.fbind("state", self.safeMode_switcher)
        self.add_widget(checkbox)

    def safe_mode(self, dt):
        # Get the number of player in current map
        playerCount = int(HACK.statis()["playerCount"])

        # If there's another player in map
        if playerCount >= 2:
            # Checking for which tools are activated
            for tool in CHECKBOXTOOLS:
                if CHECKBOXTOOLS[tool][1]:
                    # turn it off
                    CHECKBOXTOOLS[tool][0](active=False)

        # If every thing is ok, turn them on again
        else:
            for tool in CHECKBOXTOOLS:
                if CHECKBOXTOOLS[tool][1]:
                    CHECKBOXTOOLS[tool][0](active=True)


    def safeMode_switcher(self, obj, value):
        # Turn on
        if value == "down":
            self.safeMode = Clock.schedule_interval(self.safe_mode, 0.5)

        # Turn off
        else:
            self.safeMode.cancel()
            # Get all the tools back to its previous states
            for tool in CHECKBOXTOOLS:
                if CHECKBOXTOOLS[tool][1]:
                    CHECKBOXTOOLS[tool][0](active=True)




class Main(App):
    def build(self):
        return ToolScreen()


if __name__ == "__main__":
    Main().run()