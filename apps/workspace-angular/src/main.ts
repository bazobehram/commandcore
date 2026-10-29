import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';
bootstrapApplication(App, appConfig).catch(err => console.error(err));
if('serviceWorker' in navigator && location.protocol==='https:'){
  window.addEventListener('load',()=>{
    navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(err=>console.warn('PWA service worker unavailable',err));
  });
}