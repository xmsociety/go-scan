package ui

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/cmd/fyne_settings/settings"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"sync"
)

var (
	themeSettingOn = false
	headersMap     = map[int]string{
		0: "id",
		1: "IP Address",
		2: "MAC Address",
		3: "HostName",
		4: "Vendor",
	}
	devicesList = make([]map[int]interface{}, 0)
	opLock      = sync.Mutex{}
)

func MainWindow(w fyne.Window) {
	w.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu(File,
		fyne.NewMenuItem(Close, func() { w.Close() }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem(Export, func() {}),
		// a quit item will be appended to our first menu
	), fyne.NewMenu(Setting,
		fyne.NewMenuItem(Theme, func() {
			if themeSettingOn {
				return
			}
			s := settings.NewSettings()
			appearance := s.LoadAppearanceScreen(w)
			tabs := container.NewAppTabs(
				&container.TabItem{Text: "Appearance", Icon: s.AppearanceIcon(), Content: appearance})
			tabs.SetTabLocation(container.TabLocationLeading)
			themeWindow := fyne.CurrentApp().NewWindow("Theme Settings")
			themeWindow.SetContent(tabs)
			themeWindow.Show()
			themeSettingOn = true
			themeWindow.SetOnClosed(func() {
				fmt.Println("close Theme Setting")
				themeSettingOn = false
			})
			fmt.Println("Menu New")
		}),
	), fyne.NewMenu(Commands,
		fyne.NewMenuItem(StartScan, func() {
			opLock.Lock()
			defer opLock.Unlock()
		}),
	)))
	widget.NewButtonWithIcon("sss", theme.MediaPlayIcon(), func() {

	})
	_ = widget.NewToolbar(
		widget.NewToolbarAction(theme.MediaPlayIcon(), func() {}),
		widget.NewToolbarAction(theme.MediaPauseIcon(), func() {}),
		widget.NewToolbarAction(theme.DocumentCreateIcon(), func() {}),
		widget.NewToolbarAction(theme.ViewRefreshIcon(), func() {}),
	)
	//scan := canvas.NewImageFromResource(theme.MediaPlayIcon()) // init scan
	//scan.SetMinSize(fyne.NewSize(float32(100), float32(100)))

	scan := widget.NewButtonWithIcon("Start Scan", theme.MediaPlayIcon(), func() {

	})
	scanning := canvas.NewImageFromResource(theme.MediaPauseIcon()) // scanning
	//scanning.SetMinSize(fyne.NewSize(float32(100), float32(100)))
	edit := canvas.NewImageFromResource(theme.DocumentCreateIcon()) // Edit HostName
	//edit.SetMinSize(fyne.NewSize(float32(100), float32(100)))
	clear := canvas.NewImageFromResource(theme.ViewRefreshIcon()) // Clear Result
	//clear.SetMinSize(fyne.NewSize(float32(100), float32(100)))

	top := container.NewHBox(container.NewMax(scan), container.NewMax(scanning), container.NewMax(edit), container.NewMax(clear))

	top.Resize(fyne.NewSize(float32(500), float32(500)))
	tableHeaders := widget.NewTable(
		func() (int, int) { return 1, len(headersMap) - 1 },
		func() fyne.CanvasObject {
			return widget.NewLabel("placeholder")
		},
		func(id widget.TableCellID, c fyne.CanvasObject) {
			c.(*widget.Label).SetText(headersMap[id.Col+1])
		})

	content := container.NewMax(tableHeaders)
	w.SetContent(container.NewBorder(top, nil, nil, nil, content))
	w.SetMaster()
}
