package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

func SetupSystray(desk desktop.App, w fyne.Window) {
	// Set up menu
	menu := fyne.NewMenu(AppName,
		fyne.NewMenuItem(Open, w.Show),
		fyne.NewMenuItemSeparator(),
	)
	desk.SetSystemTrayMenu(menu)
}
