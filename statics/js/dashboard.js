
function Modal(modalid){
    var modal = document.getElementById(modalid)
    if (modal.classList.contains('is-active')){
      modal.classList.remove("is-active")
    }else{
      modal.classList.add("is-active");
    }
  }

  const Subscribe = async () =>{

    try { 
        const Details = {}
        Details.plan = document.getElementById("plan").value
        console.log("details",Details);

        var arrow = document.getElementById("arrow")
        var spin = document.getElementById("spin")
        arrow.style.display = "none"
        spin.style.display = "block"


        const resp = await  axios.post('/subscribe', Details,{
            headers:{
                'Content-Type': 'application/json'
            }
            
        });
        
        //  console.log(resp.data);
        if (resp.data.status==200) {
            var notify = document.getElementById("notification")
            document.getElementById('alertmsg').innerText = resp.data.msg
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
            console.log(resp);
        }

        if(resp.data.status==404){
            var notify = document.getElementById("notification")
            document.getElementById("alertmsg").innerText = resp.data.msg
            notify.classList.remove("is-primary")
            notify.classList.add("is-danger")
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
        }

    } catch (error) {
      console.log(error)
    }


  }






  const Payment = async () =>{

    try { 
        const Details = {}
        Details.paymentID = document.getElementById("paymentID").value
        Details.walletid = document.getElementById("walletid").value
        console.log("details",Details);
        var arrow = document.getElementById("arrowm")
        var spin = document.getElementById("spinm")
        arrow.style.display = "none"
        spin.style.display = "block"


        const resp = await  axios.post('/payments', Details,{
            headers:{
                'Content-Type': 'application/json'
            }
            
        });
        
        //  console.log(resp.data);
        if (resp.data.status==200) {
            var notify = document.getElementById("notificationm")
            document.getElementById('alertmsgm').innerText = resp.data.msg
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
            console.log(resp.data.msg);
        }

        if(resp.data.status==404){
            var notify = document.getElementById("notificationm")
            document.getElementById("alertmsgm").innerText = resp.data.msg
            notify.classList.remove("is-primary")
            notify.classList.add("is-danger")
            notify.style.display = "block"
            arrow.style.display = "block"
            spin.style.display = "none"
        }

    } catch (error) {
      console.log(error)
    }


  }

  const AddWallet = async ()=>{

    try { 
      const Details = {}
      Details.wallet = document.getElementById("walletid").value
      console.log("details",Details);
      var arrow = document.getElementById("arrowx")
      var spin = document.getElementById("spinx")
      arrow.style.display = "none"
      spin.style.display = "block"


      const resp = await  axios.post('/addwallet', Details,{
          headers:{
              'Content-Type': 'application/json'
          }
          
      });
      
      //  console.log(resp.data);
      if (resp.data.status==200) {
          var notify = document.getElementById("notify")
          document.getElementById('alertmsgx').innerText = resp.data.msg
          notify.style.display = "block"
          arrow.style.display = "block"
          spin.style.display = "none"
          console.log(resp);
      }

      if(resp.data.status==404){
          var notify = document.getElementById("notification")
          document.getElementById("alertmsgx").innerText = resp.data.msg
          notify.classList.remove("is-primary")
          notify.classList.add("is-danger")
          notify.style.display = "block"
          arrow.style.display = "block"
          spin.style.display = "none"
      }

  } catch (error) {
    console.log(error)
  }

  }



  const Withdraw = async ()=>{

    try { 
      console.log("clicked");
      var arrow = document.getElementById("arrowj")
      var spin = document.getElementById("spinj")
      arrow.style.display = "none"
      spin.style.display = "block"


      const resp = await  axios.get('/withdraw',{headers:{'Content-Type': 'application/json'}});
      
      //  console.log(resp.data);
      if (resp.data.status==200) {
          var notify = document.getElementById("notifyj")
          document.getElementById('alertmsgj').innerText = resp.data.msg
          notify.style.display = "block"
          arrow.style.display = "block"
          spin.style.display = "none"
          console.log(resp);
      }

      if(resp.data.status==404){
          var notify = document.getElementById("notificationj")
          document.getElementById("alertmsgj").innerText = resp.data.msg
          notify.classList.remove("is-primary")
          notify.classList.add("is-danger")
          notify.style.display = "block"
          arrow.style.display = "block"
          spin.style.display = "none"
      }

  } catch (error) {
    console.log(error)
  }

  }
  


  document.addEventListener('DOMContentLoaded', () => {
    (document.querySelectorAll('.notification .delete') || []).forEach(($delete) => {
      const $notification = $delete.parentNode;
  
      $delete.addEventListener('click', () => {
        $notification.parentNode.removeChild($notification);
      });
    });
  });



  const GetMarket= async ()=>{
    console.log('here test');
      const type = document.getElementById('mktype')
      const market = document.getElementById('market')
      console.log(type.options[type.selectedIndex].value);
      const response = await axios.get(`/markrttype/${type.options[type.selectedIndex].value}`) 
      for(i in response.data){
        const options = document.createElement('option')
        options.text = response.data[i]
        options.value = response.data[i]
        market.appendChild(options)
        console.log(response.data[i]);
      }
      console.log(response);
  }

  const GetMarketPut= async ()=>{
      const marketx = document.querySelector('#marketxxx');
      console.log('here test');
      const type = document.getElementById('mktypex')
      console.log(type.options[type.selectedIndex].value);
      const response = await axios.get(`/markrttype/${type.options[type.selectedIndex].value}`) 
      
      for(i in response.data){
        const options = document.createElement('option')
        options.text = response.data[i]
        options.value = response.data[i]
        marketx.appendChild(options)
        console.log(response.data[i]);
      }
      console.log(response);
  }