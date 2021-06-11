---
layout: post
title:  "Список «открытых» портов в системе Linux"
date:   2021-06-11 15:37:20 +0700
categories: linux
---
Бывает, по разным причинам, нужно посмотреть список ВСЕХ портов прослушиваемых системой.

Я делаю это командой:
{% highlight bash %}
sudo lsof -i -P -n | grep LISTEN
{% endhighlight %}


