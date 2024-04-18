#!/usr/bin/python
# -*- coding:utf8 -*-
# Author: CiKu370
import requests
import bs4

class upload():
    class failed(Exception):
        def __init__(self):
            Exception.__init__(self, 'Your file failed to upload!')
    def __init__(self,file):
        self.file = file
        self.url = 'https://www.datafilehost.com/upload.php'
        self.up()
    def parse(self,soup):
        a = []
        for i in soup.find_all('input'):
            a.append(i.attrs['value'])
        return ('Your file has been successfully uploaded!\nDownload link : %s\nDelete link   : %s' % (a[0],a[1]))
    def up(self):
        print('start uploading files (%s)' % self.file)
        files = {'upfile' : open(self.file , 'rb')}
        post = requests.post(self.url,files=files).text
        soup = bs4.BeautifulSoup(post,'html.parser')
        if 'Your file has been successfully uploaded!' in post:
            sendMessage(self.parse(soup))
        else:
            raise self.failed()
