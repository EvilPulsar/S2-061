import argparse
from bs4 import BeautifulSoup
import requests


tag_a = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
                      'cssStyle',
                      'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href', 'id',
                      'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
                      'labelposition',
                      'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus',
                      'onkeydown',
                      'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
                      'onselect',
                      'openTemplate', 'portletMode', 'portletUrlType', 'requiredLabel', 'requiredPosition', 'scheme',
                      'style',
                      'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig',
                      'tooltipCssClass',
                      'tooltipDelay', 'tooltipIconPath', 'value', 'windowState'}
tag_form = {'acceptcharset', 'accesskey', 'action', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
                         'cssStyle',
                         'disabled', 'enctype', 'errorPosition', 'focusElement', 'id', 'includeContext',
                         'javascriptTooltip', 'key',
                         'label', 'labelSeparator', 'labelposition', 'method', 'name', 'namespace', 'onblur',
                         'onchange', 'onclick',
                         'ondblclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove',
                         'onmouseout',
                         'onmouseover', 'onmouseup', 'onreset', 'onselect', 'onsubmit', 'openTemplate', 'portletMode',
                         'requiredLabel', 'requiredPosition', 'style', 'tabindex', 'target', 'template', 'templateDir',
                         'theme',
                         'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath',
                         'validate',
                         'value', 'windowState'}
tag_label = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
                          'errorPosition', 'for', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
                          'labelposition',
                          'name', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress',
                          'onkeyup',
                          'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect',
                          'requiredLabel',
                          'requiredLabel', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip',
                          'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value'}
tag_select = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
                           'emptyOption',
                           'errorPosition', 'headerKey', 'headerValue', 'id', 'javascriptTooltip', 'key', 'label',
                           'labelSeparator',
                           'labelposition', 'list', 'listCssClass', 'listCssStyle', 'listKey', 'listLabelKey',
                           'listTitle',
                           'listValue', 'listValueKey', 'multiple', 'name', 'onblur', 'onchange', 'onclick',
                           'ondblclick', 'onfocus',
                           'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout',
                           'onmouseover',
                           'onmouseup', 'onselect', 'requiredLabel', 'requiredPosition', 'size', 'style', 'tabindex',
                           'template',
                           'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass',
                           'tooltipDelay',
                           'tooltipIconPath', 'value'}
tag_textarea = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
                             'cssStyle',
                             'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href',
                             'id',
                             'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
                             'labelposition', 'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick',
                             'ondblclick',
                             'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove',
                             'onmouseout',
                             'onmouseover', 'onmouseup', 'onselect', 'openTemplate', 'portletMode', 'portletUrlType',
                             'requiredLabel', 'requiredPosition', 'scheme', 'style', 'tabindex', 'template',
                             'templateDir', 'theme',
                             'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath',
                             'value',
                             'windowState'}
tag_input = {'accept', 'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle',
                          'disabled',
                          'errorPosition', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator', 'labelposition',
                          'name',
                          'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress',
                          'onkeyup',
                          'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect',
                          'requiredLabel',
                          'requiredPosition', 'size', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title',
                          'tooltip',
                          'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value', 'maxLength',
                          'readonly',
                          'showPassword', 'type', 'action', 'method', 'openTemplate', 'src', 'fieldValue', 'list',
                          'listCssClass',
                          'listCssStyle', 'listKey', 'listLabelKey', 'listTitle', 'listValue', 'listValueKey', 'format'}


def get_html(url):
    try:
        res = requests.get(url=url)
        response = res.text
        return response
    except Exception as e:
        print("error : ", e, " in ", url)


def find_html(response):
    soup = BeautifulSoup(response, features="lxml")
    # 检测的话，只要找到自定义属性就好了 just find customize attribute！
    founded_list = []
    for tag in soup.find_all('a'):
        for j in tag.attrs.keys():
            if j not in tag_a:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)

    for tag in soup.find_all('form'):
        for j in tag.attrs.keys():
            if j not in tag_form:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)

    for tag in soup.find_all('label'):
        for j in tag.attrs.keys():
            if j not in tag_label:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('select'):
        for j in tag.attrs.keys():
            if j not in tag_label:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('textarea'):
        for j in tag.attrs.keys():
            if j not in tag_textarea:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('input'):
        for j in tag.attrs.keys():
            if j not in tag_input:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    return founded_list


def main(args):
    response = get_html(args.url)
    if response:
        founded_list = find_html(response)
        if founded_list:
            print('{0} exists S2-061，vulnerable tag is {1}'.format(args.url, founded_list))
        return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect CVE-2020-17530 S2-061 .https://github.com/EvilPulsar/S2-061"
                                                 "Usage：python S2_061.py -u http://example.com ")

    parser.add_argument("-u", "--url", dest="url", type=str, help="python S2_061.py -u http://example.com")
    args = parser.parse_args()
    main(args)
