import json

def savejson(his):
    prehis = {}
    with open("jsons/histr.json",'r',encoding='utf8')as file:
        prehis = json.load(file)
    his.update(prehis)
    with open("jsons/histr.json",'w',encoding='utf8')as file:
        json.dump(his,file)
    return {}

def savejson2(his):
    print(his)
    prehis = {}
    with open("jsons/saves.json",'r',encoding='utf8')as file:
        prehis = json.load(file)
    prehis.update(his)
    print(prehis)
    with open("jsons/saves.json",'w',encoding='utf8')as file:
        
        json.dump(prehis,file)
    return {}

