import express from 'express'
import cors from'cors'
import cookieParser from 'cookie-parser';
import { userRoute } from './routes/user.route.js';
import { taskRouter } from './routes/task.route.js';





const app = express();

app.use(cors({
    origin:" https://main--todo01245.netlify.app",
    // origin:"http://localhost:5173",
    credentials:true 
}))

  

app.use(cookieParser())

app.use(express.static('/public'))

app.use(express.json({
    limit:"20KB"
}))

app.use(express.urlencoded({extended:true}))


app.use("/api/v1/user",userRoute)
app.use("/api/v1/task",taskRouter)


export {app}