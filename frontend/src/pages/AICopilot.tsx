import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, Brain, ShieldAlert, Sparkles } from 'lucide-react';
import reactMarkdown from 'react-markdown';
import toast from 'react-hot-toast';

import { useStore } from '../stores/useStore';
import { api } from '../services/api';
import { ChatMessage } from '../types';

export function AICopilot() {
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    try {
      const saved = localStorage.getItem('shieldx_chat_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  
  useEffect(() => {
    localStorage.setItem('shieldx_chat_history', JSON.stringify(messages));
  }, [messages]);

  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  const { alerts, incidents, riskScore } = useStore();

  const suggestedPrompts = [
    'Why is this alert dangerous?',
    'Was customer data exposed?',
    'Show similar incidents.',
    'What should we do first?',
    'Summarize this attack.',
    'Why was this alert downgraded?',
  ];

  // Scroll to bottom on new messages
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleSendMessage = async (textToSend: string) => {
    if (!textToSend.trim() || loading) return;

    const userMessage: ChatMessage = {
      id: Math.random().toString(),
      role: 'user',
      content: textToSend,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const response = await api.chatWithAI(textToSend);
      
      const assistantMessage: ChatMessage = {
        id: Math.random().toString(),
        role: 'assistant',
        content: response.reply,
        timestamp: new Date().toLocaleTimeString(),
        provider: response.provider || 'unknown',
      };
      
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err: any) {
      toast.error(`AI reasoning failed: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-80px)] space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-900 pb-3 flex-shrink-0">
        <div>
          <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-slate-100 to-slate-400 tracking-tight flex items-center space-x-2">
            <span>AI Analyst Copilot</span>
          </h1>
          <p className="text-sm text-slate-400">
            Interactive, context-aware cybersecurity LLM copilot grounded with your current SIEM alerts database.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-xl px-4 py-2 text-xs font-semibold select-none">
            <Sparkles className="h-3.5 w-3.5" />
            <span>Real-time Context Bound</span>
          </div>
          <button
            onClick={() => {
              setMessages([]);
              localStorage.removeItem('shieldx_chat_history');
            }}
            className="px-3 py-1.5 text-xs font-semibold text-slate-400 hover:text-red-400 bg-slate-900/50 hover:bg-red-500/10 border border-slate-800 hover:border-red-500/30 rounded-lg transition-colors"
          >
            Clear History
          </button>
        </div>
      </div>

      {/* Main chat window */}
      <div className="flex-1 bg-slate-950 border border-slate-900 rounded-2xl flex flex-col min-h-0 shadow-2xl relative">
        <div className="flex-1 overflow-y-auto p-6 space-y-4 scrollbar-thin">
          {messages.length === 0 ? (
            // Empty state: Suggested prompts grid
            <div className="h-full flex flex-col justify-center items-center max-w-2xl mx-auto space-y-8 select-none py-12">
              <div className="text-center space-y-3">
                <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.2)] mx-auto animate-bounce">
                  <Bot className="h-6 w-6" />
                </span>
                <h3 className="text-lg font-bold text-slate-300">How can I assist you with these threats?</h3>
                <p className="text-xs text-slate-500 leading-relaxed">
                  I have full read access to your recent {alerts.length} ingested security logs, active incidents, and {Math.round(riskScore)}% global environment risk level. Choose a quick analysis shortcut below or write freeform questions.
                </p>
              </div>

              {/* Grid cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 w-full">
                {suggestedPrompts.map((prompt, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(prompt)}
                    className="p-4 bg-slate-900/40 border border-slate-800/80 hover:border-slate-700/60 hover:bg-slate-900/60 rounded-xl text-xs text-slate-300 font-semibold text-left transition-all hover:scale-[1.01] active:scale-[0.98] shadow-sm flex items-start space-x-2.5"
                  >
                    <span className="text-indigo-400 mt-0.5 flex-shrink-0">✦</span>
                    <span className="leading-snug">{prompt}</span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            // Chat message list
            <div className="space-y-4">
              {messages.map((msg) => {
                const isUser = msg.role === 'user';
                return (
                  <div
                    key={msg.id}
                    className={`flex ${isUser ? 'justify-end' : 'justify-start'} items-start space-x-3`}
                  >
                    {!isUser && (
                      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 flex-shrink-0 shadow-md">
                        <Bot className="h-4 w-4" />
                      </span>
                    )}
                    <div
                      className={`max-w-[75%] p-4 rounded-2xl border text-xs leading-relaxed shadow-lg ${
                        isUser
                          ? 'bg-indigo-600/90 border-indigo-500 text-white rounded-tr-none font-medium'
                          : 'bg-slate-900/80 border-slate-850 text-slate-200 rounded-tl-none font-sans font-medium'
                      }`}
                    >
                      {/* Message content */}
                      {isUser ? (
                        <p className="whitespace-pre-wrap">{msg.content}</p>
                      ) : (
                        <div className="prose prose-invert prose-xs max-w-none prose-p:leading-relaxed">
                          {React.createElement(reactMarkdown as any, {}, msg.content)}
                        </div>
                      )}
                      <div className="flex justify-between items-center mt-2 border-t border-slate-800/50 pt-2">
                        {!isUser && msg.provider && (
                          <span className={`text-[9px] font-mono select-none px-1.5 py-0.5 rounded ${
                            msg.provider === 'mock' 
                              ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' 
                              : msg.provider === 'free-gpt-4o-mini'
                              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          }`}>
                            Model: {msg.provider.toUpperCase()}
                          </span>
                        )}
                        <span className={`text-[9px] font-mono select-none ${
                          isUser ? 'text-white/40 ml-auto' : 'text-slate-500'
                        }`}>
                          {msg.timestamp}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
              {loading && (
                <div className="flex justify-start items-center space-x-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 animate-pulse flex-shrink-0">
                    <Brain className="h-4 w-4" />
                  </span>
                  <div className="bg-slate-900/60 border border-slate-850 text-slate-400 rounded-2xl rounded-tl-none p-4 text-xs font-mono flex items-center space-x-2">
                    <div className="h-1.5 w-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="h-1.5 w-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="h-1.5 w-1.5 bg-indigo-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                    <span className="ml-1 text-[10px] text-slate-500 uppercase tracking-widest font-bold">Correlating Telemetry logs...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        {/* Input Bar */}
        <div className="p-4 border-t border-slate-900 flex-shrink-0">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage(input);
            }}
            className="flex items-center space-x-3 bg-slate-900/40 border border-slate-800/80 rounded-xl px-4 py-2.5"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={loading}
              placeholder="Query threats, e.g. 'Is there a live malware outbreak?', 'Block the attacker user'..."
              className="flex-1 bg-transparent border-none text-xs text-slate-200 placeholder-slate-500 focus:outline-none disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!input.trim() || loading}
              className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white disabled:opacity-30 disabled:pointer-events-none transition-all active:scale-95 shadow-md flex-shrink-0"
            >
              <Send className="h-3.5 w-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
