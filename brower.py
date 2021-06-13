from PyQt5 import QtWidgets,QtCore,QtGui
from PyQt5.QtCore import QUrl,QEvent,QObject
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
import sys,os,requests
from PyQt5.QtWebEngineWidgets import *
import os
import socket
from time import strftime,gmtime
import readjson
import qdarkstyle
import http_client_wrapper as http
from shutil import copyfile
root = os.path.abspath(sys.argv[0])[:-10]
#重新定义QWebEngineView类，使得可以在页面内部发生跳转
class Render(QWebEngineView):
    def __init__(self, tabs):
        super(Render,self).__init__()
        self.tabs = tabs
    def createWindow(self, WebWindowType):
        newwebview = Render(self.tabs)
        self.tabs.linkturn(newwebview)
        return newwebview

#使得Render内部可以直接执linkturn功能        
class Newtab(QtWidgets.QTabWidget):
    def __init__(self,QMainWindow):
        super(Newtab,self).__init__()
        self.window = QMainWindow#使得其可以调用window中的方法属性
        
    def linkturn(self,view):#使页面跳转
        i = self.addTab(view,'')#加入选项卡
        self.setCurrentIndex(i)#tab跳转
        view.titleChanged.connect(self.window.webTitle)
        view.iconChanged.connect(self.window.webIcon)         
        view.urlChanged.connect(self.window.webHistory)
        view.page().linkHovered.connect(self.window.showUrl)
    
class UI(QMainWindow):
    def __init__(self,app):
        self.app = app
        super(UI, self).__init__()
        #########页面基本参数设置###########
        root = os.path.abspath(sys.argv[0])[:-10]
        self.setWindowTitle('Dark Eye brower')
        self.resize(680,480)
        self.setWindowIcon(QtGui.QIcon(os.path.join(root,'icons/eye.png'))) 
        ##########设置工具栏###############
        self.main_toolbar = QtWidgets.QToolBar()
        self.main_toolbar.setIconSize(QtCore.QSize(16,16))
        self.addToolBar(self.main_toolbar)    
        ###########设置下半部分的页面#########tabs
        self.tabs = Newtab(self)
        self.tabs.setTabShape(QTabWidget.Triangular)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)#一文档页面展示
        self.tabs.setTabsClosable(True)
        self.tabs_layout = QtWidgets.QGridLayout()#tab的布局
        self.tabs.setLayout(self.tabs_layout)
        settings = QWebEngineSettings.defaultSettings()
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, True)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, True)
        #######自己规定的缓存#######################
        self.hisurl = {}#记录历史浏览
        self.pagetemp = {}#缓存放每个tab的页面情况
        self.savepage = {}
        self.p = {}#记录位置在程序结束时把浏览记录存入json中，在半途需要时取出显示
        self.light = 0 
        self.setCentralWidget(self.tabs)

        
#动作创建动作以及部件
        self.status = self.statusBar()
        self.url_edit = QtWidgets.QLineEdit()#url输入框
        self.url_edit.installEventFilter(self)#安装一个事件过滤器
        self.light_button = QAction(QIcon(os.path.join(root,'icons/light.png')),'(un)light',self)
        self.save_button = QAction(QIcon(os.path.join(root,'icons/save.png')),'Savepage',self)
        self.back_button = QAction(QIcon(os.path.join(root,'icons/back.png')),'Back',self)
        self.forward_button = QAction(QIcon(os.path.join(root,'icons/forward.png')),'Forward',self)      
        self.his_button = QAction(QIcon(os.path.join(root,'icons/his.png')),'History',self) 
        self.savefile_button = QAction(QIcon(os.path.join(root,'icons/savefiles.png')),'Savedpages',self) 
        self.reload_button = QAction(QIcon(os.path.join(root,'icons/turn.png')),'Reload',self)
        self.add_button = QAction(QIcon(os.path.join(root,'icons/addpage.png')),'Addpage',self)


#向main_toolbar中添加动作以及部件
        self.main_toolbar.addAction(self.back_button)
        self.main_toolbar.addAction(self.forward_button)
        self.main_toolbar.addAction(self.reload_button)
        self.main_toolbar.addAction(self.save_button)
        self.main_toolbar.addAction(self.add_button)
        self.main_toolbar.addAction(self.savefile_button)
        self.main_toolbar.addAction(self.his_button)
        self.main_toolbar.addWidget(self.url_edit)
        self.main_toolbar.addAction(self.light_button)

################初始化行为设置#######################
        self.NewPage('new') #渲染器开始就建立一个页面
        self.reload_button.triggered.connect(self.page_reload)
        self.back_button.triggered.connect(self.page_back) 
        self.forward_button.triggered.connect(self.page_forward) 
        self.add_button.triggered.connect(lambda:self.NewPage("new"))
        self.tabs.tabCloseRequested.connect(self.Closepage)
        self.url_edit.returnPressed.connect(self.urlrecieve)
        self.savefile_button.triggered.connect(self.save)
        self.his_button.triggered.connect(self.disphis)
        self.tabs.currentChanged.connect(self.selturl2)#监听tab变换
        self.save_button.triggered.connect(self.dissave)
        self.light_button.triggered.connect(self.changecolor)
    

    def changecolor(self):
        if self.light == 0:
            self.app.setStyleSheet("")
            self.light = 1
        elif self.light == 1:
            self.app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
            self.light = 0
    def eventFilter(self, object, event):
        if object == self.url_edit:
            if event.type() == QEvent.MouseButtonRelease:
                self.url_edit.selectAll()
            
        return QObject.eventFilter(self, object, event)


        
        
    
    def urlrecieve(self):#对url框输入，检验是否正确，不正确的话弹出警告，正确保存。
        url = self.url_edit.text()
        #访问web资源到本地
        if url == "cc.scu.edu.cn":
            conn = http.connect("cc.scu.edu.cn")
            conn.setup()
            conn.requestOne_get('GET', "http://cc.scu.edu.cn/G2S/Showsystem/Index.aspx")
            path=conn.extern_path
            conn.close
            
        #构建web服务资源树
            index = self.tabs.currentIndex()
            nowview = self.tabs.widget(index)
            filepath = os.path.abspath(sys.argv[0])[:-10]+"/data/cc_scu"+path
            newname = filepath[:-4]+"html"
            copyfile(filepath,newname)
        #加载本地资源
            qurl =("file:///"+filepath)[:-4]+"html"    
            nowview = nowview.load(QUrl(qurl.replace("\\","/")))
            self.tabs.setCurrentWidget(nowview)
            index = self.tabs.currentIndex()
        else:
            if url[0:7] == "http://" or url[0:8] == "https://":
                qurl = url
            else:
                qurl = "http://" + url
        
            index = self.tabs.currentIndex()
            nowview = self.tabs.widget(index)
            nowview = nowview.load(QUrl(qurl))
            self.tabs.setCurrentWidget(nowview)
            index = self.tabs.currentIndex()

            if str(index) in self.pagetemp.keys() :
                self.pagetemp[str(index)].append(url)        
            else:           
                self.pagetemp[str(index)]=[url]
            
            
        

################################首页展示#####################################

    def NewPage(self,a):####新加页面
        view = Render(self.tabs)
        if a == "new":
            self.set_html(view)######渲染主页
        if a == "his":
            self.set_his(view)
        if a == "saves":
            self.set_saves(view)
        if a == "save":
            self.savepagehtml(view)
        i = self.tabs.addTab(view,'')#加入选项卡
        self.tabs.setCurrentIndex(i)#tab跳转
        view.titleChanged.connect(self.webTitle)
        view.iconChanged.connect(self.webIcon)         
        view.urlChanged.connect(self.webHistory)
        view.page().linkHovered.connect(self.showUrl)

    def savepagehtml(self,view):
        path =( "file:///"+os.path.abspath(sys.argv[0])[:-10]+"/readjson/save.html").replace("\\","/")
        view.load(QUrl(path))

    def set_html(self,view):
        path = ("file:///"+os.path.abspath(sys.argv[0])[:-10]+"/homepage/index.html").replace("\\","/")
        view.load(QUrl(path))

    def set_his(self,view):
        print("file:///"+root+"/readjson/Home%20page.html")
        view.load(QUrl("file:///"+root+"/readjson/Home%20page.html"))
 
    def set_saves(self,view):
        with open("saves.html", "r") as f:#temp.html是我们浏览器的首页
            html = f.read()
        view.setHtml(html)

    ######################对页面的跟踪的动作########################

    def webTitle(self, title):
        index = self.tabs.currentIndex()
        if len(title) > 16:
            title = title[0:17]
        self.tabs.setTabText(index, title)
    def webIcon(self, icon):
        index = self.tabs.currentIndex()
        self.tabs.setTabIcon(index, icon)
    def webHistory(self, url):

        if len(url.toString())<100:
            self.url_edit.setText(url.toString())
            self.hisurl[strftime("%Y-%m-%d %H:%M:%S", gmtime())] = url.toString()
            print(self.hisurl)
        index = self.tabs.currentIndex()
        currentView = self.tabs.currentWidget()
        history = currentView.history()



    #########################关闭页面############################
    def Closepage(self, index):#关闭页面，如果关到最后一个就再建一个
        if self.tabs.count() > 1:
            self.tabs.widget(index).deleteLater()
            self.tabs.removeTab(index)
        elif self.tabs.count() == 1:
            self.tabs.removeTab(0)
            self.NewPage("new")


   #########################url栏控制##############################
    def selturl2(self,index):#####url变化就改变
        if not index==-1:
            url = self.tabs.widget(index).url()
            if len(url.toString())<100:
                self.url_edit.setText(url.toString())
    def showUrl(self,url):##########底部的信息栏显示######
        self.status.showMessage(url)



  ###########################关闭总窗口时的控制#####################
    def closeEvent(self, event):#重写关闭mainwindow
        tabNum = self.tabs.count()
        closeInfo = "你打开了{}个标签页，现在确认关闭？".format(tabNum)
        if tabNum > 1:
            r = QMessageBox.question(self, "关闭浏览器", closeInfo, QMessageBox.Ok | QMessageBox.Cancel, QMessageBox.Cancel)
            if r == QMessageBox.Ok:
                event.accept()
            elif r == QMessageBox.Cancel:
                event.ignore()
        else:
            event.accept()
###############################历史记录设置####################################
    def disphis(self):
        self.hisurl = readjson.savejson(self.hisurl)
        self.NewPage("his")
        ####展示历史
    
###############################收藏夹设置#######################################    
    def save(self):
        text,ok = QtWidgets.QInputDialog.getText(self,'添加当前页面到收藏夹','书签名')
        if ok:
            index = self.tabs.currentIndex()
            self.savepage[text] = self.tabs.currentWidget().url().toString()
            print(self.savepage)
    
    def dissave(self):
        self.savepage = readjson.savejson2(self.savepage)
        self.NewPage("save")
    ##########################前进后退###########################################
    def page_forward(self):
        self.tabs.currentWidget().forward()
    def page_back(self):
        self.tabs.currentWidget().back()
    def page_reload(self):
        self.tabs.currentWidget().reload()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = UI(app)
    app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    gui.show()
    sys.exit(app.exec_())