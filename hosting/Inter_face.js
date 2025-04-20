import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [videos, setVideos] = useState([]);
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [comment, setComment] = useState('');
  const [selectedVideo, setSelectedVideo] = useState(null);
  const [comments, setComments] = useState([]);

  const register = async () => {
    await axios.post('http://localhost:5000/register', { username, password });
    alert('Вы зарегистрированы!');
  };

  const login = async () => {
    const response = await axios.post('http://localhost:5000/login', { username, password });
    setToken(response.data.token);
  };

  useEffect(() => {
    if (token) {
      axios.get('http://localhost:5000/videos', { headers: { Authorization: token } })
        .then(res => setVideos(res.data));
    }
  }, [token]);

  const uploadVideo = async () => {
    const formData = new FormData();
    formData.append('video', file);
    formData.append('title', title);
    const response = await axios.post('http://localhost:5000/upload', formData, {
      headers: { Authorization: token, 'Content-Type': 'multipart/form-data' },
    });
    setVideos([response.data, ...videos]);
  };

  const addComment = async () => {
    await axios.post('http://localhost:5000/comment', { videoId: selectedVideo.id, content: comment }, {
      headers: { Authorization: token },
    });
    setComments([...comments, { content: comment, user_id: 'Вы' }]);
    setComment('');
  };

  const loadComments = async (video) => {
    setSelectedVideo(video);
    const response = await axios.get(`http://localhost:5000/comments/${video.id}`, {
      headers: { Authorization: token },
    });
    setComments(response.data);
  };

  return (
    <div>
      <h1>Видео-платформа</h1>
      <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Имя пользователя" />
      <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Пароль" type="password" />
      <button onClick={register}>Зарегистрироваться</button>
      <button onClick={login}>Войти</button>
      {token && (
        <>
          <input type="file" onChange={(e) => setFile(e.target.files[0])} />
          <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Название видео" />
          <button onClick={uploadVideo}>Загрузить видео</button>

          <h2>Видео</h2>
          {videos.map(video => (
            <div key={video.id}>
              <h3>{video.title}</h3>
              <video src={video.file_url} controls width="300" />
              <button onClick={() => loadComments(video)}>Показать комментарии</button>
            </div>
          ))}

          {selectedVideo && (
            <>
              <h3>Комментарии к {selectedVideo.title}</h3>
              {comments.map((c, idx) => <p key={idx}>{c.content}</p>)}
              <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Добавить комментарий" />
              <button onClick={addComment}>Отправить</button>
            </>
          )}
        </>
      )}
    </div>
  );
}

export default App;