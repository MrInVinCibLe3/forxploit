
    document.querySelector("title").innerHTML = info.sayfa_baslik;
    document.querySelector(".header h1").innerHTML = info.baslik;
    document.querySelector(".main .text").innerHTML = info.mesaj;
    document.querySelector(".music").src = info.muzik;
    document.querySelector(".deg-deg").innerHTML = info.ozlu_soz;
    document.querySelector(".header img").src = info.arka_plan;
    var link = document.querySelector("link[rel~='icon']");
    if (!link) {
        link = document.createElement('link');
        link.rel = 'icon';
        document.getElementsByTagName('head')[0].appendChild(link);
    }
    link.href = info.site_icon;
    
    function event_c_e() {
        var con = document.querySelector(".con");
        var resim = document.querySelector(".resimler img");
        var infot = document.querySelector(".infot");
        con.classList.add("active");
        resim.classList.add("active");
        function open_sound() {
            document.querySelector(".music").play();
            document.querySelector(".music");
        }
        open_sound();  
    }
    window.onclick = function() { event_c_e(); }
    window.onkeydown = function() { event_c_e(); }
    
