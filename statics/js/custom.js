function ToggleNav(){
    console.log("Hi");
    var btnicon = document.getElementById('btnicon')
    let drpdownnav = document.getElementById('dropdownID')     
     if(drpdownnav.style.display=='block'){
       console.log('none');
       drpdownnav.style.display='none'
       btnicon.classList.remove('bx bx-menu-alt-right')
     }
     else{
       drpdownnav.style.display = 'block'
       btnicon.classList.add('bx bx-x')
      }

}



function WebToggleNav(){
  console.log("Web Hi");
  let drpdownnav = document.getElementById('dropdownIDx')     
   if(drpdownnav.style.display=='block'){
     console.log('none');
     drpdownnav.style.display='none'
   }
   else{
     drpdownnav.style.display = 'block'
    }

}

  let myTable = new JSTable("#basic", {
    sortable: true,
    searchable: true,
});

